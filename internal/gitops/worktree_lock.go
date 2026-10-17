package gitops

import (
	"context"
	"sync"
)

// worktreeLocks serialises the operations sharing one checkout directory: two requests on the
// same repository+branch would otherwise commit over each other's staged paths.
type worktreeLocks struct {
	mu    sync.Mutex
	locks map[string]*worktreeLock
}

// worktreeLock is a one-slot semaphore; the entry is dropped once the last holder or waiter finishes.
type worktreeLock struct {
	slot chan struct{}
	refs int
}

// lock acquires the lock for path, giving up when ctx ends; the returned release func must be deferred.
func (l *worktreeLocks) lock(ctx context.Context, path string) (func(), error) {
	l.mu.Lock()
	if l.locks == nil {
		l.locks = map[string]*worktreeLock{}
	}
	entry, ok := l.locks[path]
	if !ok {
		entry = &worktreeLock{slot: make(chan struct{}, 1)}
		l.locks[path] = entry
	}
	entry.refs++
	l.mu.Unlock()

	// Checked before the select: with a free slot and a dead context both cases are ready, and the pick must not be random.
	if err := ctx.Err(); err != nil {
		l.unref(path, entry)
		return nil, err
	}

	select {
	case entry.slot <- struct{}{}:
		var once sync.Once
		return func() { once.Do(func() { releaseSlot(entry); l.unref(path, entry) }) }, nil
	case <-ctx.Done():
		// The slot was never taken; only this caller's reference is dropped.
		l.unref(path, entry)
		return nil, ctx.Err()
	}
}

// releaseSlot gives back the slot; only the holder receives from it.
func releaseSlot(entry *worktreeLock) { <-entry.slot }

// unref drops one caller and deletes the entry once the last is gone.
func (l *worktreeLocks) unref(path string, entry *worktreeLock) {
	l.mu.Lock()
	defer l.mu.Unlock()
	entry.refs--
	if entry.refs == 0 {
		delete(l.locks, path)
	}
}
