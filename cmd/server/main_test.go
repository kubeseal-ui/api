package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// TestHealthzAlwaysOK verifies the liveness probe returns 200 regardless of config.
func TestHealthzAlwaysOK(t *testing.T) {
	rr := httptest.NewRecorder()
	healthz(rr, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}

	var body map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["status"] != "ok" {
		t.Fatalf(`expected status "ok", got %q`, body["status"])
	}
}

// TestReadyzWithoutOIDCConfigReturns503 documents that readiness fails fast
// when OIDC issuer / client id are not provided.
func TestReadyzWithoutOIDCConfigReturns503(t *testing.T) {
	rr := httptest.NewRecorder()
	handler := readyz(Config{})
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/readyz", nil))

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected status 503, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "OIDC") {
		t.Fatalf(`expected body to mention "OIDC", got %q`, rr.Body.String())
	}
}

// TestReadyzWithOIDCConfigReturns200 verifies readiness passes once OIDC is configured.
func TestReadyzWithOIDCConfigReturns200(t *testing.T) {
	cfg := Config{OIDCIssuer: "https://auth.example.com", OIDCClientID: "kubeseal-ui"}

	rr := httptest.NewRecorder()
	handler := readyz(cfg)
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/readyz", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d (body=%s)", rr.Code, rr.Body.String())
	}
}

// TestAuthLoginBuildsAuthorizeURL verifies the placeholder login handler emits
// a redirect URL composed from the configured issuer and client id.
func TestAuthLoginBuildsAuthorizeURL(t *testing.T) {
	cfg := Config{OIDCIssuer: "https://auth.example.com", OIDCClientID: "kubeseal-ui"}

	rr := httptest.NewRecorder()
	handler := authLoginRedirect(cfg)
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/v1/auth/login", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}

	var body map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	got, err := url.Parse(body["authorize_url"])
	if err != nil {
		t.Fatalf("authorize_url is not a valid URL: %v", err)
	}
	if got.Scheme != "https" || got.Host != "auth.example.com" || got.Path != "/authorize" {
		t.Fatalf("unexpected authorize_url: %s", got.String())
	}
	if got.Query().Get("client_id") != "kubeseal-ui" {
		t.Fatalf(`expected client_id "kubeseal-ui", got %q`, got.Query().Get("client_id"))
	}
	if got.Query().Get("response_type") != "code" {
		t.Fatalf(`expected response_type "code", got %q`, got.Query().Get("response_type"))
	}
}

// TestAuthLoginWithoutIssuerReturns503 ensures the handler fails closed when
// no OIDC issuer is configured rather than emitting an invalid URL.
func TestAuthLoginWithoutIssuerReturns503(t *testing.T) {
	rr := httptest.NewRecorder()
	handler := authLoginRedirect(Config{})
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/v1/auth/login", nil))

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected status 503, got %d", rr.Code)
	}
}

// TestLoadConfigDefaults verifies that flag-only invocation yields the
// documented defaults (port 8080, log-level info).
func TestLoadConfigDefaults(t *testing.T) {
	t.Setenv("KUBESEAL_API_PORT", "")
	t.Setenv("LOG_LEVEL", "")

	cfg := loadConfig()

	if cfg.Port != 8080 {
		t.Fatalf("expected default port 8080, got %d", cfg.Port)
	}
	if cfg.LogLevel != "info" {
		t.Fatalf(`expected default log level "info", got %q`, cfg.LogLevel)
	}
}

// TestLoadConfigEnableDecryptFromEnv documents the env-controlled capability flag.
func TestLoadConfigEnableDecryptFromEnv(t *testing.T) {
	cases := []struct {
		env   string
		want  bool
	}{
		{"true", true},
		{"false", false},
		{"", false},
		{"TRUE", false}, // explicit case-sensitivity: matches production semantics
	}
	for _, tc := range cases {
		t.Run(tc.env, func(t *testing.T) {
			t.Setenv("ENABLE_DECRYPT", tc.env)
			if got := loadConfig().EnableDecrypt; got != tc.want {
				t.Fatalf("ENABLE_DECRYPT=%q: want %v, got %v", tc.env, tc.want, got)
			}
		})
	}
}
