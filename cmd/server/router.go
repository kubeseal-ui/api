package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"

	authhandlers "github.com/kubeseal-ui/api/internal/auth/handlers"
	authmw "github.com/kubeseal-ui/api/internal/auth/middleware"
	"github.com/kubeseal-ui/api/internal/auth/oidc"
	"github.com/kubeseal-ui/api/internal/config"
	"github.com/kubeseal-ui/api/internal/crypto"
	"github.com/kubeseal-ui/api/internal/gitops"
	"github.com/kubeseal-ui/api/internal/handlers"
	"github.com/kubeseal-ui/api/internal/kubernetes"
	"github.com/kubeseal-ui/api/internal/metrics"
	"github.com/kubeseal-ui/api/internal/middleware"
	"github.com/kubeseal-ui/api/internal/policy"
)

func registerProtectedRoutes(r chi.Router, protected *handlers.ProtectedHandlers) {
	r.Use(middleware.BodyLimit(10 * 1024 * 1024))
	r.Get("/namespaces", protected.NamespacesHandler)
	r.Get("/secrets", protected.SecretsHandler)
	r.Get("/secrets/{namespace}/{name}", protected.SecretHandler)
	r.Get("/gitops/paths", protected.GitPathsHandler)
	r.Post("/secrets/{namespace}/{name}/diff", protected.DiffHandler)
	r.Post("/gitops/dry-run", protected.GitOpsDryRunHandler)
	r.Post("/gitops/deliver", protected.GitOpsDeliverHandler)
	r.Get("/gitops/sync", protected.GitOpsSyncStatusHandler)
	r.Post("/gitops/sync", protected.GitOpsSyncHandler)
	r.Post("/secrets/{namespace}/{name}/reveal", protected.DecryptHandler)
	// A batch has no single key to name in the path, so the keys travel in the body; the route stays
	// a PATCH on the Secret's values collection, which is what it edits.
	r.Patch("/secrets/{namespace}/{name}/values", protected.ResealHandler)
	r.Post("/secrets/encrypt", protected.EncryptHandler)
}

// routerOptions carries the router's dependencies. The transport and mapping specs are
// values-driven: a non-nil transport enables Git-backed editing, and specs seed the policy store.
type routerOptions struct {
	logger       *slog.Logger
	cfg          *config.Config
	crypto       *crypto.Wrapper
	k8s          kubernetes.Client
	transport    gitops.GitTransport
	oidcProvider oidc.AuthProvider
	mappingSpecs []policy.GitMappingSpec
	adapters     map[string]gitops.ProposalProvider
	// policyStore carries the roles, group grants, and Git mappings. It is built by main, which owns
	// the policy loader and its SIGHUP reload, so the router serves from the same store that gets
	// reloaded. A nil store gets a fresh one, which is what the router tests want.
	policyStore *policy.PolicyStore
	// readyCheck adds a readiness condition from state config.Load cannot see, such as a policy
	// document that failed to reload.
	readyCheck     func() error
	securityEvents handlers.SecurityEventSink
	metricsHandler http.Handler
}

// newRouter builds the chi router with authenticated routes. A non-nil transport constructs the
// protected handlers with their GitOps dependencies, so delivery endpoints are live; nil keeps the
// fail-closed behavior of a boot without GitOps. A seeding failure is returned so main can refuse to
// boot with a broken mapping list.
func newRouter(options routerOptions) (http.Handler, error) {
	r := chi.NewRouter()
	// OTelSpan starts a server span per request and must wrap everything, including the logger, so
	// log lines carry trace_id/span_id. Mounted unconditionally: with telemetry disabled the global
	// tracer provider is a no-op and spans cost almost nothing.
	r.Use(middleware.RequestID)
	r.Use(middleware.OTelSpan)
	r.Use(middleware.Recoverer)
	r.Use(chimw.Timeout(30 * time.Second))
	r.Use(middleware.RequestLogger(options.logger))
	r.Get("/healthz", handlers.Healthz)
	if options.readyCheck != nil {
		r.Get("/readyz", handlers.ReadyzWithCheck(options.readyCheck))
	} else {
		r.Get("/readyz", handlers.Readyz)
	}
	// /metrics serves the Prometheus exposition. The handler returns 503 when metrics are disabled, so
	// ServiceMonitor marks the target down instead of scraping an empty page silently. Unauthenticated
	// by design: the exposition carries handler/method/code labels only, no identities or names.
	if options.metricsHandler != nil {
		r.Handle("/metrics", options.metricsHandler)
	}

	logger := options.logger
	if logger == nil {
		logger = slog.Default()
	}

	// OIDC discovery is performed by main and injected here, which keeps the router free of network
	// I/O and therefore deterministic and testable.
	var provider oidc.AuthProvider
	if options.cfg != nil && options.cfg.SessionSigningKey != "" && options.oidcProvider != nil {
		provider = options.oidcProvider
	} else if options.oidcProvider != nil {
		logger.Error("SESSION_SIGNING_KEY is missing but OIDC provider is configured; /api/v1 routes will not be mounted")
	}

	policyStore := options.policyStore
	if policyStore == nil {
		policyStore = policy.NewPolicyStore()
	}
	var protected *handlers.ProtectedHandlers
	if options.transport != nil {
		protected = handlers.NewProtectedHandlersWithGitOps(policyStore, options.transport, options.k8s, options.crypto, options.cfg != nil && options.cfg.EnableDecrypt)
	} else {
		protected = handlers.NewProtectedHandlers(options.k8s, options.crypto, options.cfg != nil && options.cfg.EnableDecrypt)
	}
	// Security events flow to stdout through the redacting handler per the doc contract: one bounded
	// JSON event per reveal, patch, and delivery attempt.
	protected.SecurityEvents = options.securityEvents

	// Seed the namespace Git mappings from values. Enabled GitOps with no specs boots fail-closed:
	// delivery endpoints exist but every namespace resolves "mapping not found" until mappings are set.
	if options.transport != nil && len(options.mappingSpecs) > 0 {
		if err := policyStore.SeedGitMappings(options.mappingSpecs, options.adapters); err != nil {
			return nil, fmt.Errorf("gitops mapping seeding: %w", err)
		}
	}

	protectedRoutes := func(r chi.Router) {
		registerProtectedRoutes(r, protected)
	}

	// No provider means no auth route is exposed, preserving the fail-closed behavior in local tests
	// and unconfigured boots.
	if provider != nil {
		authCfg := authmw.DefaultAuthConfig(provider)
		authCfg.SigningKey = []byte(options.cfg.SessionSigningKey)
		authCfg.CookieSecure = true
		authCfg.CookieDomain = options.cfg.CookieDomain
		if origins := strings.Fields(options.cfg.CSRFTrustedOrigins); len(origins) > 0 {
			authCfg.CSRFTrustedOrigins = origins
		}
		authCfg.ResolveCapabilities = func(groups []string) authmw.CapabilityGrants {
			global, scoped := policyStore.NamespaceGrants(groups)
			// The outcome lands as a metric with the bounded result label only; groups never become
			// labels.
			if len(global) > 0 || len(scoped) > 0 {
				metrics.RecordOpenFGACheck("allow")
			} else {
				metrics.RecordOpenFGACheck("deny")
			}
			return authmw.CapabilityGrants{
				Global: capabilityStrings(global),
				Scoped: namespaceCapabilityStrings(scoped),
			}
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
	} else {
		logger.Warn("authenticated routes (/api/v1) disabled; running fail-closed",
			"oidc_provider_configured", options.oidcProvider != nil,
			"session_signing_key_configured", options.cfg != nil && options.cfg.SessionSigningKey != "",
		)
	}
	return r, nil
}

// capabilityStrings renders policy capabilities in the vocabulary the session identity carries.
func capabilityStrings(capabilities []policy.Capability) []string {
	result := make([]string, 0, len(capabilities))
	for _, capability := range capabilities {
		result = append(result, string(capability))
	}
	return result
}

// namespaceCapabilityStrings renders the per-namespace grants, returning nil rather than an empty map
// when there are none: an identity with only global grants should not carry an allocated map through
// every request.
func namespaceCapabilityStrings(scoped map[string][]policy.Capability) map[string][]string {
	if len(scoped) == 0 {
		return nil
	}
	result := make(map[string][]string, len(scoped))
	for namespace, capabilities := range scoped {
		result[namespace] = capabilityStrings(capabilities)
	}
	return result
}
