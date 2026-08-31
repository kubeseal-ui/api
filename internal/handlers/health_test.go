package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestHealthzAlwaysOK documents the liveness probe contract: it returns
// 200 with a JSON body as long as the process is up. Readiness is a
// separate concern (see /readyz).
func TestHealthzAlwaysOK(t *testing.T) {
	rr := httptest.NewRecorder()
	Healthz(rr, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("status: want 200, got %d", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type: want application/json, got %q", ct)
	}
	var body map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["status"] != "ok" {
		t.Errorf(`status: want "ok", got %q`, body["status"])
	}
}

// TestReadyzWithoutOIDCConfigReports503 documents that /readyz fails
// fast when required configuration is absent. Kubelet must NOT route
// traffic to a pod whose OIDC is unconfigured, because every
// authenticated endpoint would return 500.
func TestReadyzWithoutOIDCConfigReports503(t *testing.T) {
	rr := httptest.NewRecorder()
	Readyz(rr, httptest.NewRequest(http.MethodGet, "/readyz", nil))

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status: want 503, got %d", rr.Code)
	}
}

// TestReadyzWithOIDCConfigReports200 confirms readiness flips to 200
// once both OIDC values are configured. The probe reads readiness from
// the config package so the contract is in one place.
func TestReadyzWithOIDCConfigReports200(t *testing.T) {
	t.Setenv("OIDC_ISSUER", "https://auth.example.com")
	t.Setenv("OIDC_CLIENT_ID", "kubeseal-ui")

	rr := httptest.NewRecorder()
	Readyz(rr, httptest.NewRequest(http.MethodGet, "/readyz", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("status: want 200, got %d (body=%s)", rr.Code, rr.Body.String())
	}
	var body map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["status"] != "ready" {
		t.Errorf(`status: want "ready", got %q`, body["status"])
	}
}

// TestReadyzBodyIncludesReason documents the diagnostic contract: when
// not ready, the response body explains why so operators can debug
// without shelling into the pod.
func TestReadyzBodyIncludesReason(t *testing.T) {
	rr := httptest.NewRecorder()
	Readyz(rr, httptest.NewRequest(http.MethodGet, "/readyz", nil))

	var body map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["reason"] == "" {
		t.Errorf("expected reason field in not-ready response, got: %v", body)
	}
}
