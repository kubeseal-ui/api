// Package handlers hosts the kubeseal-ui api HTTP handlers: health probes and the protected
// operations mounted behind authentication and CSRF middleware.
package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/kubeseal-ui/api/internal/config"
)

// jsonResponse writes v as a JSON document with the given status code, so every handler emits a
// Content-Type header and the response envelope stays consistent.
func jsonResponse(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	// Encoding into a ResponseWriter whose status is already written can only fail on a broken
	// connection, where the request is half-served and there is nothing to recover.
	_ = json.NewEncoder(w).Encode(v)
}

// Healthz is the kubelet liveness probe: 200 as long as the process serves HTTP. It deliberately
// does not check dependencies (OIDC, K8s, cert provider) — those are /readyz. A liveness probe
// that failed on a sick downstream would have kubelet restart a pod whose api is fine.
func Healthz(w http.ResponseWriter, _ *http.Request) {
	jsonResponse(w, http.StatusOK, map[string]string{"status": "ok"})
}

// Readyz is the kubelet readiness probe: 503 until all required configuration is loaded, so
// kubelet keeps the pod out of the service endpoints until the api is usable. The contract lives
// in config.Ready(), so every caller picks up a new readiness requirement from one place.
func Readyz(w http.ResponseWriter, r *http.Request) {
	ReadyzWithCheck(nil)(w, r)
}

// ReadyzWithCheck is Readyz plus a caller-supplied check for state that config.Load() cannot see.
//
// A policy document that failed to reload keeps the last valid generation in force — right to serve,
// but not to serve silently, and readiness is where that becomes visible to a rollout. A nil check
// keeps the pre-existing behaviour exactly.
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
				"reason": "OIDC issuer or client id not configured",
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
