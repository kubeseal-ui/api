package gitops

import (
	"context"
	"sort"
	"sync"
)

// BranchSnapshot is one branch at one commit: the head, and the content of
// every file reachable from it.
type BranchSnapshot struct {
	// Commit is the branch head the file map was read at. It is the value a
	// later BaseCommit is compared against, and the one reported for a file
	// that does not exist yet.
	Commit string
	// Files maps repository-relative paths to their content at Commit.
	Files map[string][]byte
}

// BranchReader is the optional capability SnapshotTransport is built from:
// enumerate a whole branch in a single pull.
//
// It is separate from GitTransport on purpose. GitTransport is the delivery
// contract every platform satisfies; enumerating a branch is a read
// optimization that only a transport with a local worktree can offer. A
// transport that does not implement BranchReader is used unwrapped — reads go
// straight through and nothing about its behaviour changes.
type BranchReader interface {
	ReadBranch(ctx context.Context, repository, branch, authRef string) (BranchSnapshot, error)
}

// SnapshotTransport wraps a GitTransport and serves its reads from one
// per-branch snapshot held for the wrapper's lifetime. Construct one per
// request and drop it when the request ends.
//
// It exists because a namespace listing resolves drift for every Secret it
// returns, and each resolution reads Git: a templated path first, then a full
// tree walk when that path is vacant. Against a real remote every read is a
// network fetch, so a namespace of 30 Secrets issued 30–60 pulls inside one
// request and the listing approached its timeout. The reads are of the same
// branch at the same moment, and the second one is almost always answering a
// question the first already answered.
//
// So: one pull per (repository, branch) per request, one file map built from
// it, every read in that request served from the map. Request-scoped rather
// than TTL-cached, deliberately — a head that outlives the request that read it
// could let a conflicting push past the BaseCommit check, which is the one
// guarantee the delivery path depends on. One request, one snapshot, and
// freshness is exactly what it was.
//
// Writes are never served from the snapshot: DryRun and PushBranch pass
// straight through, and a successful push drops the branch's snapshot so a
// later read in the same request re-reads rather than reporting what the push
// just superseded.
//
// It is safe for concurrent use, though a handler resolving drift in a loop is
// single-goroutine.
type SnapshotTransport struct {
	// inner is the wrapped transport, used for every write and for every read
	// when reader is nil.
	inner GitTransport
	// reader is inner as a BranchReader, or nil when inner cannot enumerate a
	// branch. Non-nil is what turns memoization on.
	reader BranchReader

	mu     sync.Mutex
	states map[string]*branchState
}

// branchState holds one branch's snapshot. loaded is false once a write has
// superseded it, which makes the next read re-pull instead of answering from
// content the push replaced.
type branchState struct {
	mu       sync.Mutex
	loaded   bool
	snapshot BranchSnapshot
}

// NewSnapshotTransport wraps a transport for one request. A nil inner, or one
// that cannot enumerate a branch, yields a wrapper that is a plain pass-through
// — so callers need no special case and mock mode keeps its exact behaviour.
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

// invalidate drops a branch's snapshot after a write, so a later read in the
// same request cannot report the content the write just replaced.
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

// snapshotOf returns the branch's file map, pulling once. The per-branch lock
// is held across the pull so concurrent readers of a cold branch share one
// fetch rather than racing to issue their own.
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

// ReadManifest serves the file from the branch snapshot. A path absent from the
// map is the documented new-file vacancy, and as in the unwrapped transports
// the returned snapshot still carries the branch head — the value a new file is
// built on and the one a BaseCommit check compares against.
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
	// Copied out so a caller holding the returned slice cannot reach into the
	// map every other read in this request is served from.
	return ManifestSnapshot{Target: target, Content: append([]byte(nil), content...), Commit: snapshot.Commit}, nil
}

// SearchManifest scans the branch snapshot instead of pulling and walking the
// tree again.
//
// Paths are visited in sorted order rather than map order. A repository with
// two files claiming the same SealedSecret identity is a misconfiguration, but
// it must not make drift flap between requests, and the unwrapped tree walk it
// replaces was already ordered.
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

// DryRun passes through, snapshot or not: it must compare the caller's base
// against the live head, and answering that from a memo would defeat the check
// the write path depends on.
func (t *SnapshotTransport) DryRun(ctx context.Context, change Change, authRef string) (Diff, error) {
	return t.inner.DryRun(ctx, change, authRef)
}

// PushBranch passes through and is never memoized, then drops the branch's
// snapshot so a read after the write re-reads.
func (t *SnapshotTransport) PushBranch(ctx context.Context, change Change, authRef string) (PushResult, error) {
	result, err := t.inner.PushBranch(ctx, change, authRef)
	if err != nil {
		return result, err
	}
	branch := change.Branch
	if branch == "" {
		branch = change.Target.Branch
	}
	// Both the branch built on and the branch written to are dropped: a
	// proposal writes change.Branch while reading change.Target.Branch.
	t.invalidate(change.Target.Repository, branch)
	if branch != change.Target.Branch {
		t.invalidate(change.Target.Repository, change.Target.Branch)
	}
	return result, nil
}
