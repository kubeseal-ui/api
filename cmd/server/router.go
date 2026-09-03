package main

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"

	authhandlers "github.com/kubeseal-ui/api/internal/auth/handlers"
	authmw "github.com/kubeseal-ui/api/internal/auth/middleware"
	"github.com/kubeseal-ui/api/internal/auth/oidc"
	"github.com/kubeseal-ui/api/internal/config"
	"github.com/kubeseal-ui/api/internal/crypto"
	"github.com/kubeseal-ui/api/internal/handlers"
	"github.com/kubeseal-ui/api/internal/kubernetes"
	"github.com/kubeseal-ui/api/internal/middleware"
	"github.com/kubeseal-ui/api/internal/policy"
)

// newRouter builds the chi router with authenticated Phase 2 routes.
func newRouter(logger *slog.Logger, cfg *config.Config, cryptoWrapper *crypto.Wrapper, k8s kubernetes.Client, providers ...*oidc.Provider) http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.Recoverer)
	r.Use(chimw.Timeout(30 * time.Second))
	r.Use(middleware.RequestLogger(logger))
	r.Get("/healthz", handlers.Healthz)
	r.Get("/readyz", handlers.Readyz)

	// OIDC discovery is performed by main and injected here. Keeping the
	// router free of network I/O makes it deterministic and testable.
	var provider *oidc.Provider
	if cfg != nil && cfg.SessionSigningKey != "" && len(providers) > 0 {
		provider = providers[0]
	}

	protected := handlers.NewProtectedHandlers(k8s, cryptoWrapper, cfg != nil && cfg.EnableDecrypt)
	protectedRoutes := func(r chi.Router) {
		r.Use(middleware.BodyLimit(10 * 1024 * 1024))
		r.Get("/namespaces", protected.NamespacesHandler)
		r.Get("/secrets", protected.SecretsHandler)
		r.Get("/secrets/{namespace}/{name}", protected.SecretHandler)
		r.Post("/gitops/dry-run", protected.GitOpsDryRunHandler)
		r.Post("/gitops/deliver", protected.GitOpsDeliverHandler)
		r.Post("/secrets/{namespace}/{name}/reveal", protected.DecryptHandler)
		r.Patch("/secrets/{namespace}/{name}/values/{key}", protected.ResealHandler)
		r.Post("/secrets/encrypt", protected.EncryptHandler)
	}

	// No provider means no auth route is exposed. This preserves the
	// Phase 1 fail-closed behavior in local tests and unconfigured boots.
	if provider != nil {
		authCfg := authmw.DefaultAuthConfig(provider)
		authCfg.SigningKey = []byte(cfg.SessionSigningKey)
		authCfg.CookieSecure = true
		policyStore := policy.NewPolicyStore()
		authCfg.ResolveCapabilities = func(groups []string) []string {
			caps := policyStore.CapabilitiesForGroups(groups)
			result := make([]string, 0, len(caps))
			for _, cap := range caps {
				result = append(result, string(cap))
			}
			return result
		}
		auth := authhandlers.NewAuthHandlers(provider, authCfg, authCfg.SigningKey)
		r.Route("/api/v1", func(api chi.Router) {
			api.Get("/auth/login", auth.LoginHandler)
			api.Get("/auth/callback", auth.CallbackHandler)
			api.With(authmw.AuthMiddleware(authCfg), authmw.CSRFMiddleware(authCfg)).Post("/auth/logout", auth.LogoutHandler)
			api.With(authmw.AuthMiddleware(authCfg)).Get("/auth/me", auth.MeHandler)
			api.With(authmw.AuthMiddleware(authCfg)).Get("/auth/csrf", auth.CSRFHandler)
			api.With(authmw.AuthMiddleware(authCfg), authmw.CSRFMiddleware(authCfg)).Route("/", protectedRoutes)
		})
	}
	return r
}
