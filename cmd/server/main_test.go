package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/kubeseal-ui/api/internal/auth/oidc"
	"github.com/kubeseal-ui/api/internal/config"
	"github.com/kubeseal-ui/api/internal/crypto"
	"github.com/kubeseal-ui/api/internal/handlers"
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

func TestRegisterProtectedRoutesMountsPhase3Routes(t *testing.T) {
	r := chi.NewRouter()
	protected := handlers.NewProtectedHandlers(testK8s(), testCrypto(), false)
	registerProtectedRoutes(r, protected)
	for _, path := range []string{
		"/secrets/ns/name/diff",
		"/secrets/ns/name/reveal",
		"/secrets/ns/name/values/password",
	} {
		rr := httptest.NewRecorder()
		method := http.MethodPost
		if strings.Contains(path, "/values/") {
			method = http.MethodPatch
		}
		r.ServeHTTP(rr, httptest.NewRequest(method, path, strings.NewReader(`{}`)))
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("%s %s: status = %d, want 401", method, path, rr.Code)
		}
	}
}

type routerFakeProvider struct{}

func (routerFakeProvider) LoginURL(*oidc.FlowState) (string, error) {
	return "https://auth.example/login", nil
}
func (routerFakeProvider) ExchangeCode(context.Context, string, string) (*oidc.TokenResponse, error) {
	return nil, fmt.Errorf("not used")
}
func (routerFakeProvider) VerifyIDToken(context.Context, string, string) (*oidc.VerifiedIDToken, error) {
	return nil, fmt.Errorf("not used")
}
func (routerFakeProvider) RefreshTokens(context.Context, string) (*oidc.TokenResponse, error) {
	return nil, fmt.Errorf("not used")
}
func (routerFakeProvider) RevokeToken(context.Context, string) error { return nil }

func TestRouterProtectedPhase3RoutesRequireAuthentication(t *testing.T) {
	cfg := testConfig()
	cfg.SessionSigningKey = "router-test-signing-key"
	router := newRouter(testLogger(), cfg, testCrypto(), testK8s(), nil, routerFakeProvider{})
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/namespaces"},
		{http.MethodGet, "/api/v1/secrets"},
		{http.MethodPost, "/api/v1/secrets/ns/name/diff"},
		{http.MethodPost, "/api/v1/secrets/ns/name/reveal"},
		{http.MethodPatch, "/api/v1/secrets/ns/name/values/password"},
	} {
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, httptest.NewRequest(tc.method, tc.path, strings.NewReader(`{}`)))
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("%s %s: status = %d, want 401", tc.method, tc.path, rr.Code)
		}
	}
}

// TestRouterHealthzReturns200 verifies the liveness probe is mounted.
func TestRouterProtectedRoutesAcceptValidSessionAndCSRF(t *testing.T) {
	cfg := testConfig()
	cfg.SessionSigningKey = "router-test-signing-key"
	cfg.CSRFTrustedOrigins = "https://app.example.com"
	router := newRouter(testLogger(), cfg, testCrypto(), testK8s(), nil, routerFakeProvider{})
	csrf := "csrf-router-test"
	data := struct {
		Subject  string   `json:"sub"`
		Email    string   `json:"email"`
		Name     string   `json:"name"`
		Username string   `json:"username"`
		Groups   []string `json:"groups"`
		Expiry   int64    `json:"exp"`
		IssuedAt int64    `json:"iat"`
		CSRF     string   `json:"csrf"`
	}{"user-1", "user@example.com", "User", "user", []string{"secret-managers"}, time.Now().Add(time.Hour).Unix(), time.Now().Unix(), csrf}
	raw, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, []byte(cfg.SessionSigningKey))
	_, _ = mac.Write(raw)
	signedEnvelope := struct {
		Subject   string   `json:"sub"`
		Email     string   `json:"email"`
		Name      string   `json:"name"`
		Username  string   `json:"username"`
		Groups    []string `json:"groups"`
		Expiry    int64    `json:"exp"`
		IssuedAt  int64    `json:"iat"`
		CSRF      string   `json:"csrf"`
		Signature string   `json:"sig"`
	}{data.Subject, data.Email, data.Name, data.Username, data.Groups, data.Expiry, data.IssuedAt, data.CSRF, base64.RawURLEncoding.EncodeToString(mac.Sum(nil))}
	signed, err := json.Marshal(signedEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	session := base64.RawURLEncoding.EncodeToString(signed)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/secrets/ns/name/diff", strings.NewReader(`{"key":"password","operation":"replace","value":"new","base_commit":"abc"}`))
	req.AddCookie(&http.Cookie{Name: oidc.CookieSession, Value: session})
	req.AddCookie(&http.Cookie{Name: oidc.CookieCSRF, Value: csrf})
	req.Header.Set("X-CSRF-Token", csrf)
	req.Header.Set("Origin", "https://app.example.com")
	req.Header.Set("Idempotency-Key", "router-auth-1")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code == http.StatusUnauthorized {
		t.Fatalf("authenticated request rejected: status=%d body=%s", rr.Code, rr.Body.String())
	}
	if rr.Code == http.StatusForbidden && strings.Contains(rr.Body.String(), "CSRF") {
		t.Fatalf("CSRF rejected authenticated request: %s", rr.Body.String())
	}
	if rr.Code != http.StatusConflict && rr.Code != http.StatusBadGateway && rr.Code != http.StatusNotFound && rr.Code != http.StatusForbidden {
		t.Fatalf("request reached unexpected status=%d body=%s", rr.Code, rr.Body.String())
	}
}

// TestRouterHealthzReturns200 verifies the liveness probe is mounted.
func TestRouterHealthzReturns200(t *testing.T) {
	rr := httptest.NewRecorder()
	newRouter(testLogger(), testConfig(), testCrypto(), testK8s(), nil).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/healthz", nil))

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
	newRouter(testLogger(), cfg, testCrypto(), testK8s(), nil).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/readyz", nil))

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
	newRouter(testLogger(), testConfig(), testCrypto(), testK8s(), nil).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/readyz", nil))

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
		newRouter(testLogger(), testConfig(), testCrypto(), testK8s(), nil).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
		if rr.Code != http.StatusNotFound {
			t.Errorf("%s: want 404, got %d", path, rr.Code)
		}
	}
}
