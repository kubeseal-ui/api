// Package handlers hosts the kubeseal-ui api HTTP handlers.
//
// The router exposes health endpoints and, once OIDC is configured, mounts
// protected operations behind authentication and CSRF middleware.
package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/kubeseal-ui/api/internal/config"
)

// jsonResponse writes v as a JSON document with the given status code.
// Centralised so every handler emits a Content-Type header and so the
// response envelope stays consistent (no surprise text/html or no header).
func jsonResponse(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		// Encoding into a ResponseWriter that has already had its
		// status written can only fail on broken connections. We do
		// not try to recover — the request is already half-served.
		// Logging the error here would be the right place once we
		// have a real logger wired in main.go (P1.T10).
		_ = err
	}
}

// Healthz is the kubelet liveness probe. It returns 200 as long as the
// process is serving HTTP. It deliberately does NOT check dependencies
// (OIDC, K8s, cert provider) — those would be /readyz.
//
// If Healthz started failing because a downstream is sick, kubelet
// would restart the pod even though the api itself is fine. /readyz is
// the gate for "remove from service"; /healthz is the gate for "kill
// and restart".
func Healthz(w http.ResponseWriter, _ *http.Request) {
	jsonResponse(w, http.StatusOK, map[string]string{"status": "ok"})
}

// Readyz is the kubelet readiness probe. It returns 503 until all
// required configuration is loaded, so kubelet keeps the pod out of
// the service endpoints until the api is actually usable.
//
// Readiness is sourced from config.Ready() so the contract lives in
// one place. Adding a new readiness requirement (e.g. "cert provider
// reachable") means updating config.Ready() — every caller
// (this handler, integration tests, health checks) picks it up.
func Readyz(w http.ResponseWriter, _ *http.Request) {
	cfg, err := config.Load()
	if err != nil {
		jsonResponse(w, http.StatusServiceUnavailable, map[string]string{
			"status": "not_ready",
			"reason": "config load failed: " + err.Error(),
		})
		return
	}
	if !cfg.Ready() {
		jsonResponse(w, http.StatusServiceUnavailable, map[string]string{
			"status": "not_ready",
			"reason": "OIDC issuer or client id not configured",
		})
		return
	}
	jsonResponse(w, http.StatusOK, map[string]string{"status": "ready"})
}
