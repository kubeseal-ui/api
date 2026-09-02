package main

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"

	"github.com/kubeseal-ui/api/internal/config"
	"github.com/kubeseal-ui/api/internal/crypto"
	"github.com/kubeseal-ui/api/internal/handlers"
	"github.com/kubeseal-ui/api/internal/kubernetes"
	"github.com/kubeseal-ui/api/internal/middleware"
)

// newRouter builds the chi router. Phase 1 exposes only the health
// endpoints; the middleware chain is the production one (request ID,
// recovery, timeout, request logging) so metrics and logs are shaped
// correctly from day one.
//
// Protected routes are NOT mounted here — they are prepared for Phase 2
// where the AuthGate middleware will gate them. The parameters are
// accepted now so the wiring is complete; they are unused until Phase 2.
func newRouter(logger *slog.Logger, _ *config.Config, _ *crypto.Wrapper, _ kubernetes.Client) http.Handler {
	r := chi.NewRouter()

	// Request ID and recovery are the base layer.
	r.Use(middleware.RequestID)
	r.Use(middleware.Recoverer)
	r.Use(chimw.Timeout(30 * time.Second))
	// BodyLimit is scoped to write endpoints in Phase 2; health
	// endpoints accept no body, so no limit is mounted yet.
	r.Use(middleware.RequestLogger(logger))

	r.Get("/healthz", handlers.Healthz)
	r.Get("/readyz", handlers.Readyz)

	// Phase-2 mount point: r.Route("/api/v1", ...) with AuthGate.
	// Deliberately absent until auth exists (phase-1 boundary).
	// The handlers, crypto, and k8s client are constructed in main.go
	// so they're ready when Phase 2 adds the routes.

	return r
}