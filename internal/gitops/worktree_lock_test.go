package gitops

import (
	"context"
	"errors"
	"testing"
	"time"
)

// One shared worktree is only safe if the second caller for a directory waits for the first. The
// failure this guards against is not a lost update but a corrupted checkout: two requests adding to
// one index and committing on one HEAD.
func TestWorktreeLocksSerialiseOneDirectory(t *testing.T) {
	var locks worktreeLocks
	ctx := context.Background()

	releaseHeld, err := locks.lock(ctx, "checkout")
	if err != nil {
		t.Fatal(err)
	}

	// A different directory is not held, so it must not wait behind this one.
	releaseOther, err := locks.lock(ctx, "other")
	if err != nil {
		t.Fatal(err)
	}
	releaseOther()

	acquired := make(chan struct{})
	released := make(chan struct{})
	go func() {
		defer close(released)
		release, err := locks.lock(ctx, "checkout")
		if err != nil {
			t.Errorf("second caller: %v", err)
			return
		}
		close(acquired)
		release()
	}()

	select {
	case <-acquired:
		t.Fatal("the second caller acquired a directory the first still holds")
	case <-time.After(50 * time.Millisecond):
	}

	releaseHeld()
	select {
	case <-acquired:
	case <-time.After(2 * time.Second):
		t.Fatal("the waiter never acquired after the holder released")
	}
	// The assertion below counts references, so it must not run while the waiter is still between
	// acquiring and releasing.
	<-released

	// A caller whose request is already gone gives up rather than queueing behind a directory it can
	// no longer use for anything.
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := locks.lock(cancelled, "checkout"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled waiter: err = %v, want context.Canceled", err)
	}

	// Every caller has released, including the one that gave up, so nothing is left retained.
	locks.mu.Lock()
	defer locks.mu.Unlock()
	if len(locks.locks) != 0 {
		t.Fatalf("entries retained after every caller released: %d", len(locks.locks))
	}
}

// A waiter that gives up never took the slot, so it must not free it. Freeing it would hand the
// directory to the next caller while the holder is still inside — the exact corruption the lock
// exists to prevent, arrived at through the cancellation path rather than through a lost write.
func TestCancelledWaiterDoesNotFreeTheHeldSlot(t *testing.T) {
	var locks worktreeLocks
	releaseHeld, err := locks.lock(context.Background(), "checkout")
	if err != nil {
		t.Fatal(err)
	}

	waiting, cancelWaiting := context.WithCancel(context.Background())
	waiterDone := make(chan error, 1)
	go func() {
		_, err := locks.lock(waiting, "checkout")
		waiterDone <- err
	}()
	cancelWaiting()
	if err := <-waiterDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("waiter err = %v, want context.Canceled", err)
	}

	acquired := make(chan struct{})
	released := make(chan struct{})
	go func() {
		defer close(released)
		release, err := locks.lock(context.Background(), "checkout")
		if err != nil {
			t.Errorf("next caller: %v", err)
			return
		}
		close(acquired)
		release()
	}()
	select {
	case <-acquired:
		t.Fatal("the directory was freed by a waiter that never held it")
	case <-time.After(50 * time.Millisecond):
	}

	releaseHeld()
	select {
	case <-acquired:
	case <-time.After(2 * time.Second):
		t.Fatal("the next caller never acquired after the holder released")
	}
	<-released
}
