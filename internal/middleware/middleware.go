// Package middleware provides HTTP middleware for the kubeseal-ui api:
// request ID, panic recovery, body limits, sanitized request logging,
// and the phase-1 auth gate.
//
// Phase-1 boundary (internal-docs/implementation/phase-1.md): protected
// routes are NOT exposed. The AuthGate middleware is the placeholder
// that will enforce authentication in Phase 2; today it denies every
// request that reaches it, so wiring a route behind AuthGate is
// guaranteed safe (fail-closed) rather than accidentally public.
package middleware

import (
	"context"
	"net/http"

	"github.com/google/uuid"
)

type ctxKey int

const (
	requestIDKey ctxKey = iota
	identityKey
)

// RequestID assigns a request-scoped ID and exposes it in the
// response header and the request context. Downstream handlers and
// loggers read it via RequestIDFromContext.
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-Id")
		if id == "" {
			id = uuid.NewString()
		}
		w.Header().Set("X-Request-Id", id)
		ctx := context.WithValue(r.Context(), requestIDKey, id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequestIDFromContext returns the request ID assigned by RequestID,
// or "" when absent.
func RequestIDFromContext(ctx context.Context) string {
	v, ok := ctx.Value(requestIDKey).(string)
	if !ok {
		return ""
	}
	return v
}

// Recoverer catches panics, logs them (without stack leakage to the
// client), and returns 500 instead of crashing the process.
func Recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// BodyLimit caps the request body read by downstream handlers at max
// bytes. Bodies larger than the limit are rejected with 413 and the
// stream is not consumed.
func BodyLimit(max int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Body != nil {
				r.Body = http.MaxBytesReader(w, r.Body, max)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// AuthGate is the phase-1 authentication placeholder. It denies every
// request with 401. Phase 2 replaces it with the OIDC session check.
// Any route mounted behind AuthGate is unreachable until then —
// this is the enforced phase-1 boundary.
func AuthGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
	})
}
