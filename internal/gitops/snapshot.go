package gitops

import (
	"context"
	"sort"
	"sync"
)

// BranchSnapshot is one branch at one commit: the head, and the content of every file reachable from it.
type BranchSnapshot struct {
	// Commit is the branch head the file map was read at — what a later BaseCommit is compared against.
	Commit string
	// Files maps repository-relative paths to their content at Commit.
	Files map[string][]byte
}

// BranchReader enumerates a whole branch in a single pull; separate from GitTransport because it is
// a read optimization only a worktree-backed transport can offer — one without it is used unwrapped.
type BranchReader interface {
	ReadBranch(ctx context.Context, repository, branch, authRef string) (BranchSnapshot, error)
}

// SnapshotTransport serves one request's reads from a per-branch snapshot pulled once; construct per request, writes never served from it.
type SnapshotTransport struct {
	// inner is the wrapped transport, used for every write and for every read when reader is nil.
	inner GitTransport
	// reader is inner as a BranchReader, or nil when inner cannot enumerate a branch.
	reader BranchReader

	mu     sync.Mutex
	states map[string]*branchState
}

// branchState holds one branch's snapshot; loaded goes false after a write, so the next read re-pulls.
type branchState struct {
	mu       sync.Mutex
	loaded   bool
	snapshot BranchSnapshot
	// identity maps SealedSecret identities to their paths; built on first search, dropped with the snapshot.
	identity map[string]string
}

// load fills the state once; the caller holds state.mu, so concurrent readers of a cold branch share one fetch.
func (s *branchState) load(ctx context.Context, reader BranchReader, repository, branch, authRef string) error {
	if s.loaded {
		return nil
	}
	snapshot, err := reader.ReadBranch(ctx, repository, branch, authRef)
	if err != nil {
		return err
	}
	s.snapshot, s.loaded = snapshot, true
	return nil
}

// NewSnapshotTransport wraps a transport for one request; a nil or non-enumerating inner yields a plain pass-through.
func NewSnapshotTransport(inner GitTransport) *SnapshotTransport {
	transport := &SnapshotTransport{inner: inner, states: map[string]*branchState{}}
	if reader, ok := inner.(BranchReader); ok {
		transport.reader = reader
	}
	return transport
}

func (t *SnapshotTransport) stateFor(repository, branch string) *branchState {
	key := branchKey(repository, branch)
	t.mu.Lock()
	defer t.mu.Unlock()
	state, ok := t.states[key]
	if !ok {
		state = &branchState{}
		t.states[key] = state
	}
	return state
}

// invalidate drops a branch's snapshot after a write, so a later read cannot report the content just replaced.
func (t *SnapshotTransport) invalidate(repository, branch string) {
	key := branchKey(repository, branch)
	t.mu.Lock()
	state := t.states[key]
	t.mu.Unlock()
	if state == nil {
		return
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	state.loaded = false
	state.snapshot = BranchSnapshot{}
	state.identity = nil
}

// snapshotOf returns the branch's file map, pulling once; the per-branch lock is held across the pull.
func (t *SnapshotTransport) snapshotOf(ctx context.Context, repository, branch, authRef string) (BranchSnapshot, error) {
	state := t.stateFor(repository, branch)
	state.mu.Lock()
	defer state.mu.Unlock()
	if err := state.load(ctx, t.reader, repository, branch, authRef); err != nil {
		return BranchSnapshot{}, err
	}
	return state.snapshot, nil
}

// ReadManifest serves the file from the branch snapshot; a path absent from the map is the documented
// new-file vacancy, and the snapshot still carries the branch head a new file is built on.
func (t *SnapshotTransport) ReadManifest(ctx context.Context, target Target, authRef string) (ManifestSnapshot, error) {
	if t.reader == nil {
		return t.inner.ReadManifest(ctx, target, authRef)
	}
	snapshot, err := t.snapshotOf(ctx, target.Repository, target.Branch, authRef)
	if err != nil {
		return ManifestSnapshot{}, err
	}
	content, ok := snapshot.Files[target.Path]
	if !ok {
		return ManifestSnapshot{Target: target, Commit: snapshot.Commit}, ErrNotFound
	}
	// Copied out so a caller holding the slice cannot reach into the shared file map.
	return ManifestSnapshot{Target: target, Content: append([]byte(nil), content...), Commit: snapshot.Commit}, nil
}

// SearchManifest answers from a prebuilt identity index; an unindexed scan would parse the whole branch once per Secret.
func (t *SnapshotTransport) SearchManifest(ctx context.Context, repository, branch, namespace, name, authRef string) (ManifestSnapshot, error) {
	if t.reader == nil {
		return t.inner.SearchManifest(ctx, repository, branch, namespace, name, authRef)
	}
	state := t.stateFor(repository, branch)
	state.mu.Lock()
	defer state.mu.Unlock()
	if err := state.load(ctx, t.reader, repository, branch, authRef); err != nil {
		return ManifestSnapshot{}, err
	}
	if state.identity == nil {
		state.identity = buildIdentityIndex(state.snapshot.Files)
	}
	path, ok := lookupIdentity(state.identity, namespace, name)
	if !ok {
		return ManifestSnapshot{}, ErrNotFound
	}
	return ManifestSnapshot{
		Target:  Target{Repository: repository, Branch: branch, Path: path},
		Content: append([]byte(nil), state.snapshot.Files[path]...),
		Commit:  state.snapshot.Commit,
	}, nil
}

// buildIdentityIndex maps each SealedSecret identity to its path; sorted visit order keeps the winner
// deterministic when two files claim one identity.
func buildIdentityIndex(files map[string][]byte) map[string]string {
	paths := make([]string, 0, len(files))
	for path := range files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	index := make(map[string]string, len(paths))
	for _, path := range paths {
		for _, identity := range sealedSecretIdentities(files[path]) {
			if _, taken := index[identity]; !taken {
				index[identity] = path
			}
		}
	}
	return index
}

// PreviousManifest delegates to the wrapped transport's history read; the snapshot says nothing about earlier versions.
func (t *SnapshotTransport) PreviousManifest(ctx context.Context, target Target, authRef string) ([]byte, error) {
	history, ok := t.inner.(ManifestHistory)
	if !ok {
		return nil, ErrNoHistory
	}
	return history.PreviousManifest(ctx, target, authRef)
}

// DryRun passes through: it must compare the caller's base against the live head, not a memo.
func (t *SnapshotTransport) DryRun(ctx context.Context, change Change, authRef string) (Diff, error) {
	return t.inner.DryRun(ctx, change, authRef)
}

// PushBranch passes through, then drops the branch's snapshot so a read after the write re-reads.
func (t *SnapshotTransport) PushBranch(ctx context.Context, change Change, authRef string) (PushResult, error) {
	result, err := t.inner.PushBranch(ctx, change, authRef)
	if err != nil {
		return result, err
	}
	branch := change.Branch
	if branch == "" {
		branch = change.Target.Branch
	}
	// Both are dropped: a proposal writes change.Branch while reading change.Target.Branch.
	t.invalidate(change.Target.Repository, branch)
	if branch != change.Target.Branch {
		t.invalidate(change.Target.Repository, change.Target.Branch)
	}
	return result, nil
}
