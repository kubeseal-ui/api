// Package certprovider fetches and caches the controller's public certificate. The HTTP
// implementation is driven by KUBESEAL_CERT_URL; fetching is lazy on the first Get and
// re-fetched once the cached entry is older than the TTL, which is how key rotation is
// picked up.
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

// Provider supplies the active public certificate. Implementations must be safe for
// concurrent use.
type Provider interface {
	// Get returns the cached certificate, fetching and validating it on a miss or expiry.
	// The returned pointer must not be mutated after it is handed out.
	Get(ctx context.Context) (*x509.Certificate, error)
}

// HTTPOptions configures NewHTTP; zero fields fall back to the defaults below.
type HTTPOptions struct {
	// URL is required; the api reads it from KUBESEAL_CERT_URL.
	URL string

	TTL     time.Duration
	Timeout time.Duration

	// MaxResponseBytes bounds the response body; default 1 MiB. A real PEM cert is under
	// 10 KiB, so a runaway upstream must not be able to OOM the pod.
	MaxResponseBytes int64

	// Client is optional; nil builds one from Timeout.
	Client *http.Client
}

// httpProvider guards its fields with mu: reads happen on every encrypt request, writes
// only on a cache miss or rotation.
type httpProvider struct {
	opts HTTPOptions
	mu   sync.Mutex
	cert *x509.Certificate
	at   time.Time
	now  func() time.Time // injectable for tests
}

// NewHTTP builds an HTTP-backed Provider; it performs no network I/O until the first Get.
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

// Get implements Provider. A miss or expiry triggers a single fetch, parse, validate, and
// store.
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

// fetch issues the GET, parses and validates the PEM, and bounds the body with
// io.LimitReader so a streaming server cannot exhaust memory.
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
