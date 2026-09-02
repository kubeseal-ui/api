// Package certprovider fetches and caches the public certificate the
// api uses to seal client-side (or in-cluster) Sealed Secrets. Phase
// 1 ships an HTTP implementation driven by KUBESEAL_CERT_URL.
//
// Design:
//
//   - Provider is an interface so Phase 2+ can swap the HTTP impl for
//     a filesystem-on-startup read, a sidecar, or a mock without
//     touching call sites.
//   - Fetch is lazy (on first Get) and cached with a TTL so the
//     kubeseal controller is not hammered on every encrypt request.
//   - Rotation is handled by the TTL — once the cache entry is older
//     than TTL, the next Get triggers a fresh HTTP fetch.
//   - All network and parse errors surface to the caller; the api
//     logs them and returns 503 to clients.
package certprovider

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// Provider returns the active public certificate used to seal
// SealedSecret resources. Implementations MUST be safe for concurrent
// use by multiple goroutines.
type Provider interface {
	// Get returns the active public certificate. On cache miss or
	// expiry it fetches, parses, validates, and caches. The returned
	// pointer is safe to retain across calls — the implementation
	// MUST NOT mutate it after handing it out.
	Get(ctx context.Context) (*x509.Certificate, error)
}

// HTTPOptions configures NewHTTP. Zero-value fields fall back to
// documented defaults. Validate() rejects invalid combinations at
// construction time so misconfiguration fails fast at boot rather
// than on the first encrypt request.
type HTTPOptions struct {
	// URL is the absolute URL the GET request is issued against.
	// Required. The MVP reads it from KUBESEAL_CERT_URL.
	URL string

	// TTL is how long a fetched cert stays cached. Default 5m.
	TTL time.Duration

	// Timeout is the per-fetch network timeout. Default 5s.
	Timeout time.Duration

	// MaxResponseBytes bounds the response body the server can return
	// before we abort. Default 1 MiB — a real PEM cert is < 10 KiB;
	// a runaway server that streams gigabytes of junk must not OOM
	// the api pod.
	MaxResponseBytes int64

	// Client is the *http.Client used for fetches. Optional; when nil,
	// a client built from Timeout is used. Tests inject a Client
	// wrapping httptest.NewServer.
	Client *http.Client
}

// httpProvider is the production implementation. Fields are guarded
// by mu: reads happen on every encrypt request, writes happen only
// on cache miss / rotation.
type httpProvider struct {
	opts HTTPOptions
	mu   sync.Mutex
	cert *x509.Certificate
	at   time.Time
	now  func() time.Time // injectable for tests
}

// NewHTTP builds an HTTP-backed Provider. The provider performs no
// network I/O at construction; the first Get() call fetches.
func NewHTTP(opts HTTPOptions) Provider {
	if opts.TTL <= 0 {
		opts.TTL = 5 * time.Minute
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 5 * time.Second
	}
	if opts.MaxResponseBytes <= 0 {
		opts.MaxResponseBytes = 1 << 20 // 1 MiB
	}
	if opts.Client == nil {
		opts.Client = &http.Client{Timeout: opts.Timeout}
	}
	return &httpProvider{
		opts: opts,
		now:  time.Now,
	}
}

// Get implements Provider. Cache hits return immediately. Cache miss
// or expiry triggers a single fetch, parse, validate, and store.
func (p *httpProvider) Get(ctx context.Context) (*x509.Certificate, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.cert != nil && p.now().Sub(p.at) < p.opts.TTL {
		return p.cert, nil
	}

	cert, err := p.fetch(ctx)
	if err != nil {
		return nil, err
	}
	p.cert = cert
	p.at = p.now()
	return cert, nil
}

// fetch issues the GET, parses the PEM block, validates the cert,
// and returns the *x509.Certificate. Body is bounded by
// MaxResponseBytes — io.LimitReader aborts the read if the server
// streams beyond that.
func (p *httpProvider) fetch(ctx context.Context) (*x509.Certificate, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.opts.URL, nil)
	if err != nil {
		return nil, fmt.Errorf("cert provider: build request: %w", err)
	}
	req.Header.Set("Accept", "application/x-pem-file")

	resp, err := p.opts.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cert provider: fetch: %w", err)
	}
	defer func() {
		closeErr := resp.Body.Close()
		_ = closeErr
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("cert provider: upstream returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, p.opts.MaxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("cert provider: read body: %w", err)
	}
	if int64(len(body)) > p.opts.MaxResponseBytes {
		return nil, fmt.Errorf("cert provider: response exceeded %d bytes", p.opts.MaxResponseBytes)
	}

	block, _ := pem.Decode(body)
	if block == nil {
		return nil, fmt.Errorf("cert provider: response is not valid PEM")
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("cert provider: PEM block is %q, want CERTIFICATE", block.Type)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("cert provider: parse certificate: %w", err)
	}
	return cert, nil
}
