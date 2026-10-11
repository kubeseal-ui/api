package gitops

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// cachingTransport wraps a GitTransport and serves ReadBranch from a process-lived, per-branch
// snapshot held across requests. A drift-resolving listing pulls the remote once per branch per
// freshness window instead of once per request — the per-request SnapshotTransport still gives one
// request a single consistent commit; this is what keeps that request's cold ReadBranch from being a
// network fetch every time.
//
// Reads are safe to serve slightly stale: drift status is advisory. Writes are not cached — DryRun
// and PushBranch pass straight through to the live transport, so the BaseCommit check still runs
// against the real head, and a successful push drops the branch entry so a read-after-write re-pulls.
type cachingTransport struct {
	inner  GitTransport
	reader BranchReader // inner as a BranchReader, or nil when it cannot enumerate a branch
	ttl    time.Duration
	// now and refreshDone are injection points for tests: a fake clock, and a signal fired when a
	// background refresh finishes so a test need not sleep. Both are nil in production.
	now         func() time.Time
	refreshDone func()

	mu      sync.Mutex
	entries map[string]*branchEntry
}

// branchEntry is one branch's cached snapshot. entry.mu serialises the cold fetch (so concurrent
// first-readers share one pull) and guards refreshing (so at most one background refresh runs per
// branch at a time).
type branchEntry struct {
	mu         sync.Mutex
	loaded     bool
	fetchedAt  time.Time
	snapshot   BranchSnapshot
	refreshing bool
}

// NewCachingTransport wraps a transport with a cross-request branch cache. A non-positive ttl, a nil
// inner, or an inner that cannot enumerate a branch returns the inner unchanged, so the caller needs
// no special case and GitOps-disabled or mock boots keep their exact behaviour.
func NewCachingTransport(inner GitTransport, ttl time.Duration) GitTransport {
	if inner == nil || ttl <= 0 {
		return inner
	}
	reader, ok := inner.(BranchReader)
	if !ok {
		return inner
	}
	return &cachingTransport{
		inner:   inner,
		reader:  reader,
		ttl:     ttl,
		entries: map[string]*branchEntry{},
	}
}

func (t *cachingTransport) clock() time.Time {
	if t.now != nil {
		return t.now()
	}
	return time.Now()
}

func (t *cachingTransport) entryFor(repository, branch string) *branchEntry {
	key := branchKey(repository, branch)
	t.mu.Lock()
	defer t.mu.Unlock()
	entry, ok := t.entries[key]
	if !ok {
		entry = &branchEntry{}
		t.entries[key] = entry
	}
	return entry
}

// ReadBranch answers from the cache. Fresh within the TTL: a map lookup, no network. Expired but
// loaded: serve the stale snapshot now and refresh in the background (stale-while-revalidate), so no
// request waits on a pull except the first. Cold: block all callers on one fetch (single-flight) and
// surface its error — the listing handler then degrades that branch to drift-unknown rather than
// failing, which is the pre-existing contract.
func (t *cachingTransport) ReadBranch(ctx context.Context, repository, branch, authRef string) (BranchSnapshot, error) {
	entry := t.entryFor(repository, branch)
	entry.mu.Lock()
	if entry.loaded && t.clock().Sub(entry.fetchedAt) < t.ttl {
		snapshot := entry.snapshot
		entry.mu.Unlock()
		return snapshot, nil
	}
	if entry.loaded {
		snapshot := entry.snapshot
		if !entry.refreshing {
			entry.refreshing = true
			// Detached from the request, not torn from it: WithoutCancel keeps the request's trace
			// and span values so the background pull stays attributable, while dropping its
			// cancellation so the refresh outlives the request that triggered it — the whole point of
			// stale-while-revalidate.
			go t.refresh(context.WithoutCancel(ctx), entry, repository, branch, authRef)
		}
		entry.mu.Unlock()
		return snapshot, nil
	}
	// Cold: the fetch runs under entry.mu, so a second caller for the same cold branch blocks here
	// and then finds the entry loaded rather than racing a duplicate pull.
	defer entry.mu.Unlock()
	snapshot, err := t.reader.ReadBranch(ctx, repository, branch, authRef)
	if err != nil {
		return BranchSnapshot{}, err
	}
	entry.snapshot, entry.fetchedAt, entry.loaded = snapshot, t.clock(), true
	return snapshot, nil
}

// refresh re-pulls a stale branch off the request path. It runs on a detached, bounded context
// because the request that triggered it may already have returned. fetchedAt advances only on
// success, so a failed refresh keeps serving the last-good snapshot and is retried on the next read;
// the refreshing flag means a persistent failure costs one background pull per read, not a herd.
func (t *cachingTransport) refresh(ctx context.Context, entry *branchEntry, repository, branch, authRef string) {
	defer func() {
		if t.refreshDone != nil {
			t.refreshDone()
		}
	}()
	ctx, cancel := context.WithTimeout(ctx, t.ttl)
	defer cancel()
	snapshot, err := t.reader.ReadBranch(ctx, repository, branch, authRef)
	entry.mu.Lock()
	defer entry.mu.Unlock()
	entry.refreshing = false
	if err != nil {
		return
	}
	entry.snapshot, entry.fetchedAt = snapshot, t.clock()
}

// invalidate drops a branch entry so the next read re-pulls. Called after a push so a user sees the
// change they just delivered rather than the pre-push snapshot.
func (t *cachingTransport) invalidate(repository, branch string) {
	key := branchKey(repository, branch)
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.entries, key)
}

// ReadManifest, SearchManifest, and DryRun pass through. The per-request SnapshotTransport serves its
// reads from ReadBranch, so these are reached only by a caller using this transport unwrapped; DryRun
// must always see the live head for its base check.
func (t *cachingTransport) ReadManifest(ctx context.Context, target Target, authRef string) (ManifestSnapshot, error) {
	return t.inner.ReadManifest(ctx, target, authRef)
}

func (t *cachingTransport) SearchManifest(ctx context.Context, repository, branch, namespace, name, authRef string) (ManifestSnapshot, error) {
	return t.inner.SearchManifest(ctx, repository, branch, namespace, name, authRef)
}

func (t *cachingTransport) DryRun(ctx context.Context, change Change, authRef string) (Diff, error) {
	return t.inner.DryRun(ctx, change, authRef)
}

// PushBranch passes through and then drops the branch's cached snapshot, so a read after the write
// re-pulls. Both branches are dropped: a proposal writes change.Branch while reading
// change.Target.Branch.
func (t *cachingTransport) PushBranch(ctx context.Context, change Change, authRef string) (PushResult, error) {
	result, err := t.inner.PushBranch(ctx, change, authRef)
	if err != nil {
		return result, err
	}
	branch := change.Branch
	if branch == "" {
		branch = change.Target.Branch
	}
	t.invalidate(change.Target.Repository, branch)
	if branch != change.Target.Branch {
		t.invalidate(change.Target.Repository, change.Target.Branch)
	}
	return result, nil
}

// PreviousManifest delegates to the wrapped transport's history when it has one, so the "which side
// moved" explanation keeps working through the cache. Nothing here is cached: it reads once, for the
// one Secret whose divergence is being explained.
func (t *cachingTransport) PreviousManifest(ctx context.Context, target Target, authRef string) ([]byte, error) {
	history, ok := t.inner.(ManifestHistory)
	if !ok {
		return nil, ErrNoHistory
	}
	return history.PreviousManifest(ctx, target, authRef)
}

// WarmTarget names one branch to pull before any user asks for it.
type WarmTarget struct{ Repository, Branch, AuthRef string }

// PrewarmBranches pulls each distinct branch once, in the background and bounded in parallel, so the
// per-branch cache is warm before the first request rather than making that request wait on a cold
// clone. Call it at startup, off the serving path. A transport that cannot enumerate branches is a
// no-op; even with caching disabled the pull still lands the on-disk worktree, so the first real
// read is a fetch rather than a clone.
func PrewarmBranches(ctx context.Context, transport GitTransport, targets []WarmTarget, logger *slog.Logger) {
	reader, ok := transport.(BranchReader)
	if !ok || len(targets) == 0 {
		return
	}
	seen := map[string]bool{}
	distinct := make([]WarmTarget, 0, len(targets))
	for _, target := range targets {
		if target.Repository == "" || target.Branch == "" {
			continue
		}
		key := branchKey(target.Repository, target.Branch)
		if seen[key] {
			continue
		}
		seen[key] = true
		distinct = append(distinct, target)
	}

	const maxConcurrent = 4
	sem := make(chan struct{}, maxConcurrent)
	var wg sync.WaitGroup
	for _, target := range distinct {
		wg.Add(1)
		sem <- struct{}{}
		go func(target WarmTarget) {
			defer wg.Done()
			defer func() { <-sem }()
			if _, err := reader.ReadBranch(ctx, target.Repository, target.Branch, target.AuthRef); err != nil && logger != nil {
				// Not fatal: a branch that fails to warm stays cold and the first request that needs
				// it pays the pull, exactly as it would have without prewarming.
				logger.Warn("gitops branch prewarm failed", "repository", target.Repository, "branch", target.Branch, "error", err)
			}
		}(target)
	}
	wg.Wait()
}
