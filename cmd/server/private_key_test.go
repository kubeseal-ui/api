package main

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/kubeseal-ui/api/internal/kubernetes"
)

// countingClient counts key-list calls so a test can tell a cache hit from a fresh read. Embedding
// the interface supplies the rest of the client for free.
type countingClient struct {
	kubernetes.Client
	calls int
}

func (c *countingClient) FindAllControllerKeys(ctx context.Context) ([]kubernetes.ActiveKey, error) {
	c.calls++
	return c.Client.FindAllControllerKeys(ctx)
}

// keyedClient is the deterministic fake with one parsable controller key installed. The fake only
// checks that both Secret keys are present, so the certificate need not be real and the private key
// need only parse.
func keyedClient(t *testing.T) kubernetes.Client {
	t.Helper()
	key, err := rsa.GenerateKey(nil, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	encoded := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	return kubernetes.NewFake(nil, nil, []kubernetes.Secret{{
		ObjectMeta: kubernetes.ObjectMeta{Name: "sealed-secrets-key-1"},
		Data:       map[string][]byte{"tls.crt": []byte("cert"), "tls.key": encoded},
	}})
}

// TestPrivateKeyProviderReusesListWithinTTL is the point of the cache: a reveal and the reseal that
// follows it inside the window must not each pay a live Secrets list.
func TestPrivateKeyProviderReusesListWithinTTL(t *testing.T) {
	now := time.Unix(0, 0)
	client := &countingClient{Client: keyedClient(t)}
	provider := newKubePrivateKeyProvider(client, func() time.Time { return now })

	first, err := provider.PrivateKeys(context.Background())
	if err != nil {
		t.Fatalf("PrivateKeys: %v", err)
	}
	if len(first) != 1 {
		t.Fatalf("keys = %d, want 1", len(first))
	}
	if client.calls != 1 {
		t.Fatalf("list calls = %d, want 1", client.calls)
	}

	now = now.Add(keyCacheTTL - time.Second)
	if _, err := provider.PrivateKeys(context.Background()); err != nil {
		t.Fatalf("PrivateKeys inside the TTL: %v", err)
	}
	if client.calls != 1 {
		t.Fatalf("list calls inside the TTL = %d, want 1", client.calls)
	}

	// Expiry is the only thing that re-reads on its own, which is how a rotated key is picked up
	// without a restart.
	now = now.Add(2 * time.Second)
	if _, err := provider.PrivateKeys(context.Background()); err != nil {
		t.Fatalf("PrivateKeys after expiry: %v", err)
	}
	if client.calls != 2 {
		t.Fatalf("list calls after expiry = %d, want 2", client.calls)
	}
}

// TestPrivateKeyProviderInvalidationForcesReread covers the path crypto.DecryptYAML takes when no
// supplied key opened the data. The clock deliberately does not move, so a pass here cannot come
// from expiry.
func TestPrivateKeyProviderInvalidationForcesReread(t *testing.T) {
	now := time.Unix(0, 0)
	client := &countingClient{Client: keyedClient(t)}
	provider := newKubePrivateKeyProvider(client, func() time.Time { return now })

	if _, err := provider.PrivateKeys(context.Background()); err != nil {
		t.Fatalf("PrivateKeys: %v", err)
	}
	provider.InvalidateKeyCache()
	if _, err := provider.PrivateKeys(context.Background()); err != nil {
		t.Fatalf("PrivateKeys after invalidation: %v", err)
	}
	if client.calls != 2 {
		t.Fatalf("list calls = %d, want 2", client.calls)
	}
}

// TestPrivateKeyProviderDoesNotCacheFailure keeps a transient Kubernetes error from being pinned for
// the TTL: the next request must try again rather than replay the failure.
func TestPrivateKeyProviderDoesNotCacheFailure(t *testing.T) {
	client := &countingClient{Client: kubernetes.NewFake(nil, nil, nil)}
	provider := newKubePrivateKeyProvider(client, nil)

	for attempt := 1; attempt <= 2; attempt++ {
		if _, err := provider.PrivateKeys(context.Background()); err == nil {
			t.Fatalf("attempt %d: want an error when no key parses", attempt)
		}
	}
	if client.calls != 2 {
		t.Fatalf("list calls = %d, want 2", client.calls)
	}
}
