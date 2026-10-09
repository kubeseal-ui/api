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

// testCertPEM returns a real self-signed EC certificate as PEM bytes; the implementation
// must parse real PEM, so the tests do not use fake strings.
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

// TestHTTPProviderCaching asserts the upstream call count as well as the returned
// certificate: returning a cached value without it would still pass if the impl happened
// to return the same cert twice by accident.
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

// A stuck controller cert endpoint must not stall every encrypt request.
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

// An oversized response must be rejected rather than OOM the pod; the boundary is read
// through io.LimitReader.
func TestHTTPProviderResponseSizeLimit(t *testing.T) {
	pemBytes := testCertPEM(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Garbage ahead of the PEM pushes the body past the 1024-byte limit.
		padding := strings.Repeat("A", 1024)
		w.Header().Set("Content-Type", "application/x-pem-file")
		_, _ = w.Write([]byte(padding + pemBytes))
	}))
	defer srv.Close()

	p := NewHTTP(HTTPOptions{
		URL:              srv.URL,
		MaxResponseBytes: 1024, // deliberately tiny to trigger rejection
	})

	_, err := p.Get(t.Context())
	if err == nil {
		t.Fatal("expected size-limit error, got nil")
	}
	if !strings.Contains(err.Error(), "exceeded") {
		t.Errorf("expected 'exceeded' in error, got: %v", err)
	}
}

// A valid HTTP status with non-PEM content must fail rather than hand the caller a nil or
// partially-parsed cert.
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

// Past the TTL the next Get must re-fetch, which is how rotation is picked up.
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

	if _, err := p.Get(t.Context()); err != nil {
		t.Fatalf("first Get: %v", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("after first Get: upstream calls=%d, want 1", got)
	}

	if _, err := p.Get(t.Context()); err != nil {
		t.Fatalf("second Get: %v", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("within TTL: upstream calls=%d, want 1 (cached)", got)
	}

	time.Sleep(150 * time.Millisecond)
	if _, err := p.Get(t.Context()); err != nil {
		t.Fatalf("third Get: %v", err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("after TTL expiry: upstream calls=%d, want 2 (rotated)", got)
	}
}
