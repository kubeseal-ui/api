package main

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/kubeseal-ui/api/internal/crypto"
	"github.com/kubeseal-ui/api/internal/kubernetes"
)

// Shorter than the certificate TTL: a cert only has to create new ciphertext, while a key must open existing ciphertext — the stale
// window is one where a just-rotated key cannot be revealed, which crypto.DecryptYAML's invalidate-and-retry closes.
const keyCacheTTL = 60 * time.Second

// kubePrivateKeyProvider adapts the Kubernetes client to crypto.PrivateKeyProvider, reusing the parsed list for keyCacheTTL;
// the mutex is held across a miss so concurrent callers share one round trip.
type kubePrivateKeyProvider struct {
	client kubernetes.Client
	now    func() time.Time

	mu     sync.Mutex
	keys   []*rsa.PrivateKey
	loaded time.Time
}

// The retry that makes the cache safe lives in crypto.DecryptYAML via this interface; the assertion keeps a rename from silently disabling it.
var _ crypto.KeyCacheInvalidator = (*kubePrivateKeyProvider)(nil)

// newKubePrivateKeyProvider builds the production provider. A nil now means time.Now.
func newKubePrivateKeyProvider(client kubernetes.Client, now func() time.Time) *kubePrivateKeyProvider {
	if now == nil {
		now = time.Now
	}
	return &kubePrivateKeyProvider{client: client, now: now}
}

// PrivateKeys returns every controller key the cluster still holds, not just the active one — the controller retains old keys so it
// can still decrypt what they sealed. The list is reused for keyCacheTTL, or every reveal pays a live Secrets list plus a parse per key.
func (p *kubePrivateKeyProvider) PrivateKeys(ctx context.Context) ([]*rsa.PrivateKey, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.keys != nil && p.now().Sub(p.loaded) < keyCacheTTL {
		return p.keys, nil
	}

	keys, err := p.loadKeys(ctx)
	if err != nil {
		// Not cached: a failed list is retried on the next request rather than pinned for the TTL.
		return nil, err
	}
	p.keys = keys
	p.loaded = p.now()
	return keys, nil
}

// InvalidateKeyCache drops the cached list so the next call re-reads the cluster; DecryptYAML calls it when no supplied key opened the data,
// which is the signature of a key rotated inside the TTL.
func (p *kubePrivateKeyProvider) InvalidateKeyCache() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.keys = nil
}

// loadKeys lists the controller's labelled Secrets and parses the usable ones; one unreadable key must not disable the others.
func (p *kubePrivateKeyProvider) loadKeys(ctx context.Context) ([]*rsa.PrivateKey, error) {
	keys, err := p.client.FindAllControllerKeys(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*rsa.PrivateKey, 0, len(keys))
	for _, key := range keys {
		parsed, err := parseRSAPrivateKeyPEM(key.Key)
		if err != nil {
			slog.Warn("skipping unreadable controller key", "key", key.Name, "error", err)
			continue
		}
		out = append(out, parsed)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no usable controller key among %d labelled secrets", len(keys))
	}
	return out, nil
}

func parseRSAPrivateKeyPEM(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("controller key is not PEM")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse controller key: %w", err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("controller key is not RSA")
	}
	return key, nil
}
