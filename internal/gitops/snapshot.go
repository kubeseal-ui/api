package gitops

import (
	"context"
	"sort"
	"sync"
)

// BranchSnapshot is one branch at one commit: the head, and the content of every file reachable
// from it.
type BranchSnapshot struct {
	// Commit is the branch head the file map was read at — the value a later BaseCommit is
	// compared against, and the one reported for a file that does not exist yet.
	Commit string
	// Files maps repository-relative paths to their content at Commit.
	Files map[string][]byte
}

// BranchReader is the optional capability SnapshotTransport is built from: enumerate a whole branch
// in a single pull.
//
// It is separate from GitTransport on purpose: enumerating a branch is a read optimization only a
// transport with a local worktree can offer, and a transport without it is used unwrapped — reads
// pass straight through and its behaviour is unchanged.
type BranchReader interface {
	ReadBranch(ctx context.Context, repository, branch, authRef string) (BranchSnapshot, error)
}

// SnapshotTransport wraps a GitTransport and serves its reads from one per-branch snapshot held for
// the wrapper's lifetime; construct one per request. One pull per (repository, branch), one file map
// built from it, every read in that request served from the map — a namespace listing resolves drift
// for every Secret it returns, and against a real remote each of those reads is a network fetch.
//
// Request-scoped rather than TTL-cached, deliberately: a head that outlived the request could let a
// conflicting push past the BaseCommit check. Writes are never served from the snapshot.
type SnapshotTransport struct {
	// inner is the wrapped transport, used for every write and for every read when reader is nil.
	inner GitTransport
	// reader is inner as a BranchReader, or nil when inner cannot enumerate a branch. Non-nil is
	// what turns memoization on.
	reader BranchReader

	mu     sync.Mutex
	states map[string]*branchState
}

// branchState holds one branch's snapshot. loaded is false once a write has superseded it, which
// makes the next read re-pull instead of answering from content the push replaced.
type branchState struct {
	mu       sync.Mutex
	loaded   bool
	snapshot BranchSnapshot
}

// NewSnapshotTransport wraps a transport for one request. A nil inner, or one that cannot
// enumerate a branch, yields a plain pass-through, so callers need no special case and mock mode
// keeps its exact behaviour.
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

// invalidate drops a branch's snapshot after a write, so a later read in the same request cannot
// report the content the write just replaced.
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
}

// snapshotOf returns the branch's file map, pulling once. The per-branch lock is held across the
// pull so concurrent readers of a cold branch share one fetch rather than racing.
func (t *SnapshotTransport) snapshotOf(ctx context.Context, repository, branch, authRef string) (BranchSnapshot, error) {
	state := t.stateFor(repository, branch)
	state.mu.Lock()
	defer state.mu.Unlock()
	if !state.loaded {
		snapshot, err := t.reader.ReadBranch(ctx, repository, branch, authRef)
		if err != nil {
			return BranchSnapshot{}, err
		}
		state.snapshot, state.loaded = snapshot, true
	}
	return state.snapshot, nil
}

// ReadManifest serves the file from the branch snapshot. A path absent from the map is the
// documented new-file vacancy, and as in the unwrapped transports the returned snapshot still
// carries the branch head — what a new file is built on and what a BaseCommit check compares
// against.
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
	// Copied out so a caller holding the returned slice cannot reach into the map every other
	// read in this request is served from.
	return ManifestSnapshot{Target: target, Content: append([]byte(nil), content...), Commit: snapshot.Commit}, nil
}

// SearchManifest scans the branch snapshot instead of pulling and walking the tree again.
//
// Paths are visited in sorted order rather than map order: two files claiming the same
// SealedSecret identity is a misconfiguration, but it must not make drift flap between requests,
// and the tree walk this replaces was already ordered.
func (t *SnapshotTransport) SearchManifest(ctx context.Context, repository, branch, namespace, name, authRef string) (ManifestSnapshot, error) {
	if t.reader == nil {
		return t.inner.SearchManifest(ctx, repository, branch, namespace, name, authRef)
	}
	snapshot, err := t.snapshotOf(ctx, repository, branch, authRef)
	if err != nil {
		return ManifestSnapshot{}, err
	}
	paths := make([]string, 0, len(snapshot.Files))
	for path := range snapshot.Files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		if MatchesSealedSecret(snapshot.Files[path], namespace, name) {
			return ManifestSnapshot{
				Target:  Target{Repository: repository, Branch: branch, Path: path},
				Content: append([]byte(nil), snapshot.Files[path]...),
				Commit:  snapshot.Commit,
			}, nil
		}
	}
	return ManifestSnapshot{}, ErrNotFound
}

// PreviousManifest delegates to the wrapped transport when it can read history, and reports
// ErrNoHistory when it cannot. Nothing here is memoized or invalidated: the snapshot is the branch
// head's file map, which says nothing about earlier versions, and the answer is read once — for the
// one Secret whose divergence is being explained.
func (t *SnapshotTransport) PreviousManifest(ctx context.Context, target Target, authRef string) ([]byte, error) {
	history, ok := t.inner.(ManifestHistory)
	if !ok {
		return nil, ErrNoHistory
	}
	return history.PreviousManifest(ctx, target, authRef)
}

// DryRun passes through: it must compare the caller's base against the live head, and answering
// that from a memo would defeat the check the write path depends on.
func (t *SnapshotTransport) DryRun(ctx context.Context, change Change, authRef string) (Diff, error) {
	return t.inner.DryRun(ctx, change, authRef)
}

// PushBranch passes through and is never memoized, then drops the branch's snapshot so a read
// after the write re-reads.
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
