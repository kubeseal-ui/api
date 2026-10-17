// Package handlers hosts the kubeseal-ui api HTTP handlers: health probes and the protected operations behind auth+CSRF middleware.
package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/kubeseal-ui/api/internal/config"
)

// jsonResponse writes v as JSON so every handler emits a Content-Type header and the envelope stays consistent.
func jsonResponse(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		// Status line already committed; nothing to turn this into but the log.
		slog.Error("failed to encode response body", "error", err)
	}
}

// Healthz is the liveness probe; deliberately dependency-free, or kubelet would restart a pod whose api is fine.
func Healthz(w http.ResponseWriter, _ *http.Request) {
	jsonResponse(w, http.StatusOK, map[string]string{"status": "ok"})
}

// Readyz is the readiness probe: 503 until required configuration is loaded, keeping the pod out of service endpoints.
func Readyz(w http.ResponseWriter, r *http.Request) {
	ReadyzWithCheck(nil)(w, r)
}

// ReadyzWithCheck adds a caller-supplied check for state config.Load() cannot see — where a failed
// policy reload (last valid generation still in force) becomes visible to a rollout.
func ReadyzWithCheck(check func() error) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
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
				"reason": "OIDC issuer, client id, or session signing key not configured",
			})
			return
		}
		if check != nil {
			if checkErr := check(); checkErr != nil {
				jsonResponse(w, http.StatusServiceUnavailable, map[string]string{
					"status": "not_ready",
					"reason": "configuration reload failed: " + checkErr.Error(),
				})
				return
			}
		}
		jsonResponse(w, http.StatusOK, map[string]string{"status": "ready"})
	}
}
