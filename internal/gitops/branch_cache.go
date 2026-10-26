package gitops

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// cachingTransport serves ReadBranch from a process-lived per-branch snapshot: one remote pull per
// branch per TTL (stale-while-revalidate) instead of one per request. Writes pass straight through
// so the BaseCommit check always sees the live head; a successful push drops the branch entry.
type cachingTransport struct {
	inner  GitTransport
	reader BranchReader // inner as a BranchReader, or nil when it cannot enumerate a branch
	ttl    time.Duration
	// now and refreshDone are test injection points (fake clock, refresh-finished signal); nil in production.
	now         func() time.Time
	refreshDone func()

	mu      sync.Mutex
	entries map[string]*branchEntry
	// history memoizes PreviousManifest answers by (branch, path, head commit); a head fixes its
	// history, so a hit needs no remote round-trip. Capped, evicting the whole map when full.
	history map[string][]byte
}

// branchEntry is one branch's cached snapshot; entry.mu serialises the cold fetch and the background refresh.
type branchEntry struct {
	mu         sync.Mutex
	loaded     bool
	fetchedAt  time.Time
	snapshot   BranchSnapshot
	refreshing bool
}

// NewCachingTransport returns inner unchanged for a non-positive ttl, a nil inner, or one that cannot enumerate a branch.
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
		history: map[string][]byte{},
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

// ReadBranch serves fresh entries from the cache, expired ones stale-while-revalidate, and blocks cold
// callers on a single shared fetch whose error surfaces to the listing handler.
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
			// Detached, not torn: WithoutCancel keeps the request's trace values while dropping its cancellation.
			go t.refresh(context.WithoutCancel(ctx), entry, repository, branch, authRef)
		}
		entry.mu.Unlock()
		return snapshot, nil
	}
	// Cold: the fetch runs under entry.mu, so a second caller blocks and then finds the entry loaded.
	defer entry.mu.Unlock()
	snapshot, err := t.reader.ReadBranch(ctx, repository, branch, authRef)
	if err != nil {
		return BranchSnapshot{}, err
	}
	entry.snapshot, entry.fetchedAt, entry.loaded = snapshot, t.clock(), true
	return snapshot, nil
}

// refresh re-pulls a stale branch off the request path; fetchedAt advances only on success, so failures keep serving last-good.
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

// invalidate drops a branch entry after a push, so the next read re-pulls.
func (t *cachingTransport) invalidate(repository, branch string) {
	key := branchKey(repository, branch)
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.entries, key)
}

// ReadManifest, SearchManifest, and DryRun pass through; DryRun must always see the live head.
func (t *cachingTransport) ReadManifest(ctx context.Context, target Target, authRef string) (ManifestSnapshot, error) {
	return t.inner.ReadManifest(ctx, target, authRef)
}

func (t *cachingTransport) SearchManifest(ctx context.Context, repository, branch, namespace, name, authRef string) (ManifestSnapshot, error) {
	return t.inner.SearchManifest(ctx, repository, branch, namespace, name, authRef)
}

func (t *cachingTransport) DryRun(ctx context.Context, change Change, authRef string) (Diff, error) {
	return t.inner.DryRun(ctx, change, authRef)
}

// PushBranch passes through, then drops both the written branch and the read branch (a proposal writes change.Branch, reads change.Target.Branch).
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

// maxHistoryEntries bounds the previous-version memo; a full reset at the cap is cheaper than an LRU
// and the map repopulates with the entries actually being viewed.
const maxHistoryEntries = 512

// PreviousManifest answers from a head-keyed memo: the branch snapshot names the head, and the same
// head has the same previous version, so repeated detail reads between pushes never touch the
// history checkout. A push drops the branch entry, so the next read keys on the new head and misses.
func (t *cachingTransport) PreviousManifest(ctx context.Context, target Target, authRef string) ([]byte, error) {
	history, ok := t.inner.(ManifestHistory)
	if !ok {
		return nil, ErrNoHistory
	}
	snapshot, err := t.ReadBranch(ctx, target.Repository, target.Branch, authRef)
	if err != nil {
		// A branch fetch failure must not newly fail a read that previously answered; the memo is an
		// optimization, so fall through to the live history read.
		return history.PreviousManifest(ctx, target, authRef)
	}
	key := target.Repository + "\x00" + target.Branch + "\x00" + target.Path + "\x00" + snapshot.Commit
	t.mu.Lock()
	previous, hit := t.history[key]
	t.mu.Unlock()
	if hit {
		return previous, nil
	}
	previous, err = history.PreviousManifest(ctx, target, authRef)
	if err != nil {
		return nil, err
	}
	t.mu.Lock()
	if len(t.history) >= maxHistoryEntries {
		t.history = map[string][]byte{}
	}
	t.history[key] = previous
	t.mu.Unlock()
	return previous, nil
}

// WarmTarget names one branch to pull before any user asks for it.
type WarmTarget struct{ Repository, Branch, AuthRef string }

// PrewarmBranches pulls each distinct branch once, bounded in parallel, off the serving path; call at startup.
// A transport that cannot enumerate branches is a no-op.
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
				// Not fatal: a branch that fails to warm stays cold and the first request pays the pull.
				logger.Warn("gitops branch prewarm failed", "repository", target.Repository, "branch", target.Branch, "error", err)
			}
		}(target)
	}
	wg.Wait()
}
