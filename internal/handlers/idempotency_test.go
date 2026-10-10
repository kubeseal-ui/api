package handlers

import (
	"strconv"
	"testing"
	"time"
)

// idempotencyTestClock is a hand-cranked time source, so the TTL can be crossed without sleeping.
type idempotencyTestClock struct{ t time.Time }

func (c *idempotencyTestClock) now() time.Time          { return c.t }
func (c *idempotencyTestClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newIdempotencyTestStore() (*idempotencyStore, *idempotencyTestClock) {
	c := &idempotencyTestClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	store := newIdempotencyStore()
	store.now = c.now
	return store, c
}

func TestIdempotencyStoreRefusesARepeatInsideTheTTL(t *testing.T) {
	store, clock := newIdempotencyTestStore()
	if !store.claim("k") {
		t.Fatal("first claim = false, want true")
	}
	clock.advance(idempotencyTTL - time.Second)
	if store.claim("k") {
		t.Fatal("repeat inside the TTL = true, want false")
	}
}

func TestIdempotencyStoreForgetsAKeyAfterTheTTL(t *testing.T) {
	store, clock := newIdempotencyTestStore()
	if !store.claim("k") {
		t.Fatal("first claim = false, want true")
	}
	clock.advance(idempotencyTTL + time.Second)
	if !store.claim("k") {
		t.Fatal("claim after the TTL = false, want true")
	}
}

// The store must not grow without limit. A burst of distinct keys inside one TTL window is all live
// at once, so expiring alone cannot bound it — this is the case the cap exists for.
func TestIdempotencyStoreIsBoundedByTheCap(t *testing.T) {
	store, _ := newIdempotencyTestStore()
	total := idempotencyMaxKeys * 2
	for i := 0; i < total; i++ {
		store.claim("key-" + strconv.Itoa(i))
	}
	if len(store.entries) > idempotencyMaxKeys {
		t.Fatalf("entries = %d, want at most %d", len(store.entries), idempotencyMaxKeys)
	}
	if len(store.order) != len(store.entries) {
		t.Fatalf("order = %d, entries = %d, want them equal", len(store.order), len(store.entries))
	}
	// Eviction drops the oldest claims, so the newest is the one still held.
	if store.claim("key-" + strconv.Itoa(total-1)) {
		t.Fatal("the most recent key was evicted, want it retained")
	}
}

// Re-claiming after expiry appends to the order, so the sweep must leave the map and the order
// agreeing about which keys are live.
func TestIdempotencyStoreSweepKeepsOrderConsistent(t *testing.T) {
	store, clock := newIdempotencyTestStore()
	for i := 0; i < 10; i++ {
		store.claim("old-" + strconv.Itoa(i))
	}
	clock.advance(idempotencyTTL + time.Second)
	for i := 0; i < 10; i++ {
		if !store.claim("new-" + strconv.Itoa(i)) {
			t.Fatalf("claim %d after expiry = false, want true", i)
		}
	}
	if len(store.entries) != 10 || len(store.order) != 10 {
		t.Fatalf("entries = %d, order = %d, want 10 and 10", len(store.entries), len(store.order))
	}
	if store.claim("new-0") {
		t.Fatal("re-claim of a live key = true, want false")
	}
}
