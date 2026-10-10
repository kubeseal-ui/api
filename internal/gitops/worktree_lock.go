package gitops

import (
	"context"
	"sync"
)

// worktreeLocks serialises the operations that share one checkout directory.
//
// The lock is per directory, not per transport. A checkout path is keyed on repository and branch,
// so two requests for the same namespace share one index and one HEAD: without this, one request's
// commit can sweep in another's staged path, and the broken-entry recovery can delete a directory
// another request is mid-push in.
type worktreeLocks struct {
	mu    sync.Mutex
	locks map[string]*worktreeLock
}

// worktreeLock is a one-slot semaphore plus a count of the callers holding or waiting for it, so the
// entry is dropped once the last of them finishes and the map does not grow with every key seen.
type worktreeLock struct {
	slot chan struct{}
	refs int
}

// lock acquires the lock for path, giving up when ctx ends rather than queueing work for a request
// that is already gone. The returned release func must be deferred by the caller.
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

	// Checked before the select, not only inside it: when the slot is free and the context is
	// already dead both cases of the select are ready, and a coin flip would sometimes run a whole
	// Git operation for a request that is already gone.
	if err := ctx.Err(); err != nil {
		l.unref(path, entry)
		return nil, err
	}

	select {
	case entry.slot <- struct{}{}:
		var once sync.Once
		return func() { once.Do(func() { releaseSlot(entry); l.unref(path, entry) }) }, nil
	case <-ctx.Done():
		// The slot was never taken. Freeing it here would hand the lock to the next caller while
		// the current holder is still inside, so only this caller's reference is dropped.
		l.unref(path, entry)
		return nil, ctx.Err()
	}
}

// releaseSlot gives back the slot this caller took. Only the holder receives from it, so a plain
// receive takes exactly its own token.
func releaseSlot(entry *worktreeLock) { <-entry.slot }

// unref drops one caller and deletes the entry once the last holder and waiter is gone, so the map
// does not grow with every key ever seen.
func (l *worktreeLocks) unref(path string, entry *worktreeLock) {
	l.mu.Lock()
	defer l.mu.Unlock()
	entry.refs--
	if entry.refs == 0 {
		delete(l.locks, path)
	}
}
