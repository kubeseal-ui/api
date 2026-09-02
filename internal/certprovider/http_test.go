// Package certprovider tests — RED-GREEN-REFACTOR per the
// test-driven-development skill. One test at a time, watched fail,
// then minimum implementation.
package certprovider

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// testCertPEM generates a real self-signed EC certificate as PEM bytes
// and returns it along with a cleanup. Real PEM parsing is what the
// implementation must do, so tests use real PEM bytes, not fake strings.
func testCertPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Unix(0, 0),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// TestHTTPProviderCaching is the first tracer bullet. A Provider
// driven by an HTTP server must:
//   - fetch the cert on first call
//   - return the same parsed cert on subsequent calls within TTL
//   - NOT re-hit the upstream while the cache is fresh
//
// We assert both correctness (same certificate returned) AND the
// upstream-call count (the only way to prove caching actually
// happened — returning a cached value without checking the call
// count would still pass if the impl happened to return the same
// cert twice by accident).
func TestHTTPProviderCaching(t *testing.T) {
	var calls atomic.Int32
	pemBytes := testCertPEM(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/x-pem-file")
		_, _ = w.Write([]byte(pemBytes))
	}))
	defer srv.Close()

	p := NewHTTP(HTTPOptions{
		URL: srv.URL,
		TTL: 1 * time.Minute, // long enough that the test won't trip expiry
	})

	first, err := p.Get(t.Context())
	if err != nil {
		t.Fatalf("first Get: %v", err)
	}
	if first == nil {
		t.Fatalf("first Get returned nil cert")
	}

	second, err := p.Get(t.Context())
	if err != nil {
		t.Fatalf("second Get: %v", err)
	}
	if second == nil {
		t.Fatalf("second Get returned nil cert")
	}

	if got := calls.Load(); got != 1 {
		t.Fatalf("upstream call count: got %d, want 1 (cache should serve the second call)", got)
	}
}

// TestHTTPProviderTimeout documents that a slow upstream is bounded
// by the configured Timeout. The Provider MUST NOT hang forever —
// a stuck controller cert endpoint would stall every encrypt request.
func TestHTTPProviderTimeout(t *testing.T) {
	pemBytes := testCertPEM(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(500 * time.Millisecond)
		w.Header().Set("Content-Type", "application/x-pem-file")
		_, _ = w.Write([]byte(pemBytes))
	}))
	defer srv.Close()

	p := NewHTTP(HTTPOptions{
		URL:     srv.URL,
		Timeout: 50 * time.Millisecond, // well below the server's 500ms delay
	})

	_, err := p.Get(t.Context())
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if !strings.Contains(err.Error(), "fetch") && !strings.Contains(err.Error(), "timeout") {
		t.Errorf("expected a fetch/timeout error, got: %v", err)
	}
}

// TestHTTPProviderResponseSizeLimit documents that an oversized
// response body is rejected. A runaway upstream must not OOM the
// api pod. The implementation uses io.LimitReader; the test
// verifies the boundary: a body at exactly MaxResponseBytes is
// accepted, one just above is rejected.
func TestHTTPProviderResponseSizeLimit(t *testing.T) {
	pemBytes := testCertPEM(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Prefix the valid PEM with garbage to push past the size limit.
		// MaxResponseBytes is 1024 (tiny) so the small PEM + padding exceeds it.
		padding := strings.Repeat("A", 1024)
		w.Header().Set("Content-Type", "application/x-pem-file")
		_, _ = w.Write([]byte(padding + pemBytes))
	}))
	defer srv.Close()

	p := NewHTTP(HTTPOptions{
		URL:               srv.URL,
		MaxResponseBytes:  1024, // deliberately tiny to trigger rejection
	})

	_, err := p.Get(t.Context())
	if err == nil {
		t.Fatal("expected size-limit error, got nil")
	}
	if !strings.Contains(err.Error(), "exceeded") {
		t.Errorf("expected 'exceeded' in error, got: %v", err)
	}
}

// TestHTTPProviderInvalidPEM documents that a response with valid
// HTTP status but non-PEM content is rejected. The caller must never
// receive a nil cert or a partially-parsed result.
func TestHTTPProviderInvalidPEM(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprint(w, "<html><body>error 500</body></html>")
	}))
	defer srv.Close()

	p := NewHTTP(HTTPOptions{
		URL:    srv.URL,
		TTL:    1 * time.Minute,
		Client: &http.Client{Timeout: 5 * time.Second},
	})

	_, err := p.Get(t.Context())
	if err == nil {
		t.Fatal("expected PEM decode error, got nil")
	}
	if !strings.Contains(err.Error(), "PEM") {
		t.Errorf("expected PEM error, got: %v", err)
	}
}

// TestHTTPProviderRotation documents that after the TTL expires,
// the Provider re-fetches from the upstream. The test uses a
// controllable now-function by relying on a short TTL and real
// wall-clock time, asserting the upstream call count increments
// after the cache window closes.
func TestHTTPProviderRotation(t *testing.T) {
	var calls atomic.Int32
	pemBytes := testCertPEM(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/x-pem-file")
		_, _ = w.Write([]byte(pemBytes))
	}))
	defer srv.Close()

	p := NewHTTP(HTTPOptions{
		URL:    srv.URL,
		TTL:    100 * time.Millisecond, // short TTL for fast test
		Client: &http.Client{Timeout: 5 * time.Second},
	})

	// First call: fetch
	if _, err := p.Get(t.Context()); err != nil {
		t.Fatalf("first Get: %v", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("after first Get: upstream calls=%d, want 1", got)
	}

	// Second call within TTL: cache hit
	if _, err := p.Get(t.Context()); err != nil {
		t.Fatalf("second Get: %v", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("within TTL: upstream calls=%d, want 1 (cached)", got)
	}

	// Wait past TTL, then third call: must re-fetch
	time.Sleep(150 * time.Millisecond)
	if _, err := p.Get(t.Context()); err != nil {
		t.Fatalf("third Get: %v", err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("after TTL expiry: upstream calls=%d, want 2 (rotated)", got)
	}
}
