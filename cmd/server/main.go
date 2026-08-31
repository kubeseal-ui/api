// Package main implements the kubeseal-ui API server.
//
// The server is intentionally minimal for the MVP CI gate: it exposes
// health/readiness probes and a small set of placeholder auth routes that
// match the eventual OIDC Authorization Code + PKCE flow. The full
// capability model, Sealed Secrets crypto wrapper, GitOps delivery, and
// Kubernetes client wiring live behind these handlers and will be added
// in subsequent phases per internal-docs/engineering/backend/*.md.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

// Config holds the runtime configuration for the kubeseal-ui API server.
type Config struct {
	Port         int
	LogLevel     string
	OIDCIssuer   string
	OIDCClientID string
	EnableDecrypt bool
}

var (
	flagPort  = flag.Int("port", 8080, "TCP port the API server binds to")
	flagLevel = flag.String("log-level", "info", "slog log level (debug|info|warn|error)")
)

// loadConfig applies environment overrides on top of the parsed flag values.
// Flag registration happens in init() so the global flag set is defined only
// once per process — calling loadConfig multiple times (notably from tests)
// would otherwise panic with "flag redefined".
func loadConfig() Config {
	port := *flagPort
	level := *flagLevel
	if v := os.Getenv("KUBESEAL_API_PORT"); v != "" {
		fmt.Sscanf(v, "%d", &port)
	}
	if v := os.Getenv("LOG_LEVEL"); v != "" {
		level = v
	}
	return Config{
		Port:          port,
		LogLevel:      level,
		OIDCIssuer:    os.Getenv("OIDC_ISSUER"),
		OIDCClientID:  os.Getenv("OIDC_CLIENT_ID"),
		EnableDecrypt: os.Getenv("ENABLE_DECRYPT") == "true",
	}
}

// jsonResponse writes v as JSON with the given status code.
func jsonResponse(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("failed to encode JSON response", "error", err)
	}
}

// healthz is a liveness probe: the process is up.
func healthz(w http.ResponseWriter, _ *http.Request) {
	jsonResponse(w, http.StatusOK, map[string]string{"status": "ok"})
}

// readyz is a readiness probe: required configuration is present.
func readyz(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		if cfg.OIDCIssuer == "" || cfg.OIDCClientID == "" {
			jsonResponse(w, http.StatusServiceUnavailable, map[string]string{
				"status": "not_ready",
				"reason": "OIDC issuer or client id not configured",
			})
			return
		}
		jsonResponse(w, http.StatusOK, map[string]string{"status": "ready"})
	}
}

// authLoginRedirect returns the OIDC authorize URL placeholder. The real
// implementation constructs the Authorization Code + PKCE flow.
func authLoginRedirect(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if cfg.OIDCIssuer == "" {
			http.Error(w, "OIDC issuer not configured", http.StatusServiceUnavailable)
			return
		}
		jsonResponse(w, http.StatusOK, map[string]string{
			"authorize_url": fmt.Sprintf("%s/authorize?response_type=code&client_id=%s", cfg.OIDCIssuer, cfg.OIDCClientID),
			"request_id":    middleware.GetReqID(r.Context()),
		})
	}
}

// authCallback handles the OIDC redirect. Placeholder: returns 501 until
// the full PKCE code-exchange flow is implemented.
func authCallback(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "OIDC callback not yet implemented", http.StatusNotImplemented)
}

// authLogout terminates the local session. Placeholder: always 204.
func authLogout(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

// authMe returns the authenticated principal. Placeholder: 401.
func authMe(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "unauthenticated", http.StatusUnauthorized)
}

// newRouter builds the chi router with middleware and the public route set.
func newRouter(cfg Config) http.Handler {
	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))

	r.Get("/healthz", healthz)
	r.Get("/readyz", readyz(cfg))

	r.Route("/api/v1", func(r chi.Router) {
		r.Get("/auth/login", authLoginRedirect(cfg))
		r.Get("/auth/callback", authCallback)
		r.Post("/auth/logout", authLogout)
		r.Get("/auth/me", authMe)
	})

	return r
}

func main() {
	flag.Parse()
	cfg := loadConfig()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	router := newRouter(cfg)
	server := &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.Port),
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		slog.Info("starting kubeseal-ui api", "port", cfg.Port, "oidc_issuer", cfg.OIDCIssuer)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("server error", "error", err)
			stop()
		}
	}()

	<-ctx.Done()
	slog.Info("shutting down kubeseal-ui api")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		slog.Error("server shutdown error", "error", err)
	}
}
