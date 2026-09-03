package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kubeseal-ui/api/internal/config"
	"github.com/kubeseal-ui/api/internal/crypto"
	"github.com/kubeseal-ui/api/internal/kubernetes"
)

// testLogger discards log output; individual middleware tests cover
// log content.
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

type testCertProvider struct{}

func (t *testCertProvider) Get(_ context.Context) (*x509.Certificate, error) {
	return nil, fmt.Errorf("test cert provider")
}

func testConfig() *config.Config {
	return &config.Config{
		Port:            8080,
		LogLevel:        "info",
		OIDCIssuer:      "https://auth.example.com",
		OIDCClientID:    "kubeseal-ui",
		EnableDecrypt:   false,
		KubeSealCertURL: "",
		FakeK8sClient:   true,
	}
}

func testCrypto() *crypto.Wrapper {
	return crypto.New(&testCertProvider{}, nil)
}

func testK8s() kubernetes.Client {
	return kubernetes.NewFake(
		[]kubernetes.Namespace{{Name: "default"}, {Name: "kube-system"}},
		[]kubernetes.SealedSecret{
			{Name: "example", Namespace: "default", Scope: "strict"},
		},
		nil,
	)
}

// TestRouterHealthzReturns200 verifies the liveness probe is mounted.
func TestRouterHealthzReturns200(t *testing.T) {
	rr := httptest.NewRecorder()
	newRouter(testLogger(), testConfig(), testCrypto(), testK8s()).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	var body map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["status"] != "ok" {
		t.Fatalf(`want status "ok", got %q`, body["status"])
	}
}

// TestRouterReadyzReturns503WithoutConfig verifies readiness fails
// closed when OIDC is unconfigured.
func TestRouterReadyzReturns503WithoutConfig(t *testing.T) {
	t.Setenv("OIDC_ISSUER", "")
	t.Setenv("OIDC_CLIENT_ID", "")

	cfg := testConfig()
	cfg.OIDCIssuer = ""
	cfg.OIDCClientID = ""

	rr := httptest.NewRecorder()
	newRouter(testLogger(), cfg, testCrypto(), testK8s()).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/readyz", nil))

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503, got %d", rr.Code)
	}
}

// TestRouterReadyzReturns200WithConfig verifies readiness passes with
// the required configuration present.
func TestRouterReadyzReturns200WithConfig(t *testing.T) {
	t.Setenv("OIDC_ISSUER", "https://auth.example.com")
	t.Setenv("OIDC_CLIENT_ID", "kubeseal-ui")

	rr := httptest.NewRecorder()
	newRouter(testLogger(), testConfig(), testCrypto(), testK8s()).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/readyz", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d (body=%s)", rr.Code, rr.Body.String())
	}
}

// TestRouterDoesNotExposeProtectedRoutes enforces the Phase-1
// boundary: /api/v1 must not exist until auth is implemented.
func TestRouterDoesNotExposeProtectedRoutes(t *testing.T) {
	for _, path := range []string{
		"/api/v1/auth/login",
		"/api/v1/namespaces",
		"/api/v1/secrets",
	} {
		rr := httptest.NewRecorder()
		newRouter(testLogger(), testConfig(), testCrypto(), testK8s()).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
		if rr.Code != http.StatusNotFound {
			t.Errorf("%s: want 404, got %d", path, rr.Code)
		}
	}
}
