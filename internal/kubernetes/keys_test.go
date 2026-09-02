package kubernetes

import (
	"context"
	"testing"
	"time"
)

// TestFakeClientFindActiveKeyNewestTimestamp verifies the newest
// valid key wins.
func TestFakeClientFindActiveKeyNewestTimestamp(t *testing.T) {
	old := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	newer := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	f := NewFake(nil, nil, []Secret{
		keySecret("old-key", old, true),
		keySecret("new-key", newer, true),
	})

	got, err := f.FindActiveControllerKey(context.Background())
	if err != nil {
		t.Fatalf("FindActiveControllerKey: %v", err)
	}
	if got.Name != "new-key" {
		t.Errorf("want new-key, got %q", got.Name)
	}
	if string(got.Key) != "key-material" {
		t.Errorf("key bytes mismatch")
	}
}

// TestFakeClientFindActiveKeyNameTieBreaker verifies that with equal
// timestamps the lexicographically smaller name wins deterministically.
func TestFakeClientFindActiveKeyNameTieBreaker(t *testing.T) {
	same := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)

	f := NewFake(nil, nil, []Secret{
		keySecret("z-key", same, true),
		keySecret("a-key", same, true),
	})

	got, err := f.FindActiveControllerKey(context.Background())
	if err != nil {
		t.Fatalf("FindActiveControllerKey: %v", err)
	}
	if got.Name != "a-key" {
		t.Errorf("want a-key (name tie-breaker), got %q", got.Name)
	}
}

// TestFakeClientFindActiveKeyMalformedFailsClosed verifies that
// entries missing tls.crt or tls.key are rejected, and no valid key
// at all fails closed.
func TestFakeClientFindActiveKeyMalformedFailsClosed(t *testing.T) {
	f := NewFake(nil, nil, []Secret{
		keySecret("no-key", time.Now(), false), // tls.crt only
	})
	if _, err := f.FindActiveControllerKey(context.Background()); err == nil {
		t.Fatal("want error when the only candidate is malformed")
	}

	empty := NewFake(nil, nil, nil)
	if _, err := empty.FindActiveControllerKey(context.Background()); err == nil {
		t.Fatal("want error when no keys exist")
	}
}

// TestFakeClientFindActiveKeyMissingTLSField verifies that a key
// missing tls.key is filtered out even when a valid newer one exists.
func TestFakeClientFindActiveKeyMissingTLSField(t *testing.T) {
	old := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	newer := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	f := NewFake(nil, nil, []Secret{
		keySecret("newer-broken", newer, false), // newest but malformed
		keySecret("old-valid", old, true),
	})

	got, err := f.FindActiveControllerKey(context.Background())
	if err != nil {
		t.Fatalf("FindActiveControllerKey: %v", err)
	}
	if got.Name != "old-valid" {
		t.Errorf("want old-valid (malformed newest ignored), got %q", got.Name)
	}
}

// TestFakeClientFindActiveKeyAmbiguousFailsClosed verifies that two
// keys with the SAME name AND timestamp are indistinguishable and
// fail closed rather than silently picking one.
func TestFakeClientFindActiveKeyAmbiguousFailsClosed(t *testing.T) {
	same := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)

	f := NewFake(nil, nil, []Secret{
		keySecret("dup-key", same, true),
		keySecret("dup-key", same, true),
	})

	if _, err := f.FindActiveControllerKey(context.Background()); err == nil {
		t.Fatal("want error for ambiguous identical keys")
	}
}
