package kubernetes

import (
	"context"
	"testing"
	"time"
)

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

// Decryption must reach every key the controller still holds, not just the active one:
// that is what lets a SealedSecret sealed before a key rotation still be decrypted.
func TestFakeClientFindAllKeysReturnsEveryRetainedKey(t *testing.T) {
	old := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	newer := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	f := NewFake(nil, nil, []Secret{
		keySecret("old-key", old, true),
		keySecret("broken", newer, false), // tls.crt only
		keySecret("new-key", newer, true),
	})

	got, err := f.FindAllControllerKeys(context.Background())
	if err != nil {
		t.Fatalf("FindAllControllerKeys: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 valid keys, got %d: %+v", len(got), got)
	}
	seen := make(map[string]bool, len(got))
	for _, k := range got {
		seen[k.Name] = true
		if string(k.Key) != "key-material" {
			t.Errorf("key %q: bytes mismatch", k.Name)
		}
	}
	for _, want := range []string{"old-key", "new-key"} {
		if !seen[want] {
			t.Errorf("missing retained key %q", want)
		}
	}
}

func TestFakeClientFindAllKeysFailsClosed(t *testing.T) {
	empty := NewFake(nil, nil, nil)
	if _, err := empty.FindAllControllerKeys(context.Background()); err == nil {
		t.Fatal("want error when no keys exist")
	}

	malformed := NewFake(nil, nil, []Secret{keySecret("no-key", time.Now(), false)})
	if _, err := malformed.FindAllControllerKeys(context.Background()); err == nil {
		t.Fatal("want error when the only candidate is malformed")
	}
}
