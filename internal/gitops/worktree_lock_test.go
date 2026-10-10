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
	go func() {
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
