// Package main wires the kubeseal-ui api server.
//
// The server exposes health endpoints and authenticated Phase 2 API routes.
package main

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/kubeseal-ui/api/internal/acl"
	authmw "github.com/kubeseal-ui/api/internal/auth/middleware"
	"github.com/kubeseal-ui/api/internal/auth/oidc"
	"github.com/kubeseal-ui/api/internal/certprovider"
	"github.com/kubeseal-ui/api/internal/config"
	"github.com/kubeseal-ui/api/internal/crypto"
	"github.com/kubeseal-ui/api/internal/kubernetes"
	"github.com/kubeseal-ui/api/internal/observability"
	"k8s.io/client-go/rest"
)

// devPrivProvider is a development-only PrivateKeyProvider that returns
// a fixed RSA key for local testing when ENABLE_DECRYPT=true.
// Production uses the Kubernetes-backed provider.
type devPrivProvider struct {
	key *rsa.PrivateKey
}

func (d *devPrivProvider) PrivateKey(_ context.Context) (*rsa.PrivateKey, error) {
	return d.key, nil
}

func main() {
	flag.Parse()
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "config: %v\n", err)
		os.Exit(1)
	}

	logger := observability.NewLogger(os.Stdout, slog.LevelInfo)
	slog.SetDefault(logger)

	// Phase 1: construct all providers and services but DO NOT wire
	// protected routes. The chi router only exposes /healthz and /readyz.
	// Protected handlers are compiled and unit-tested but remain unreachable
	// until Phase 2 adds the auth middleware.

	// Certificate provider (lazy fetch + TTL cache)
	var certProvider certprovider.Provider
	if cfg.KubeSealCertURL != "" {
		certProvider = certprovider.NewHTTP(certprovider.HTTPOptions{
			URL: cfg.KubeSealCertURL,
		})
	} else {
		slog.Warn("KUBESEAL_CERT_URL not set; encryption will fail until configured")
		certProvider = &staticCertProvider{} // placeholder that returns error
	}

	// Kubernetes client (fake in explicit fake mode; production client otherwise)
	var k8sClient kubernetes.Client
	if cfg.FakeK8sClient {
		k8sClient = kubernetes.NewFake(
			[]kubernetes.Namespace{{Name: "default"}, {Name: "kube-system"}},
			[]kubernetes.SealedSecret{
				{Name: "example", Namespace: "default", Scope: "strict"},
			},
			nil,
		)
	} else {
		kubeConfig, configErr := rest.InClusterConfig()
		if configErr != nil {
			log.Fatal("kubernetes config", "error", configErr)
		}
		k8sClient, configErr = kubernetes.NewClientFromConfig(kubeConfig, kubernetes.Options{ControllerNamespace: cfg.ControllerNamespace, ActiveKeyLabel: cfg.ActiveKeyLabel})
		if configErr != nil {
			log.Fatal("kubernetes client", "error", configErr)
		}
	}

	var privProvider crypto.PrivateKeyProvider
	if cfg.EnableDecrypt {
		if cfg.FakeK8sClient {
			privProvider = &devPrivProvider{key: devPrivateKey()}
		} else {
			privProvider = kubePrivateKeyProvider{client: k8sClient}
		}
	}
	cryptoWrapper := crypto.New(certProvider, privProvider)

	// ACL identities (mock for Phase 1; OIDC in Phase 2)
	_ = acl.RoleViewer
	_ = acl.RoleEditor
	_ = acl.RoleSecretManager
	_ = acl.RolePlatformAdmin

	// Router with production middleware chain (request ID, recovery, timeout, logging)
	// OIDC discovery is injected by the server startup path.
	var oidcProvider *oidc.Provider
	if cfg.OIDCIssuer != "" && cfg.OIDCClientID != "" {
		oidcCfg := oidc.Config{
			IssuerURL: cfg.OIDCIssuer, ClientID: cfg.OIDCClientID,
			ClientSecret: cfg.OIDCClientSecret, RedirectURL: cfg.OIDCRedirectURL,
			Scopes: strings.Fields(cfg.OIDCScopes), GroupsClaim: cfg.OIDCGroupsClaim,
			UsernameClaim: cfg.OIDCUsernameClaim, CookieSecure: true,
		}
		if len(oidcCfg.Scopes) == 0 {
			oidcCfg.Scopes = []string{"openid", "profile", "email", "groups"}
		}
		if oidcCfg.GroupsClaim == "" {
			oidcCfg.GroupsClaim = "groups"
		}
		if oidcCfg.UsernameClaim == "" {
			oidcCfg.UsernameClaim = "preferred_username"
		}
		if oidcCfg.ClientSecret == "" || oidcCfg.RedirectURL == "" {
			slog.Error("OIDC configuration incomplete", "error", "client secret and redirect URL are required")
		} else {
			discoveryCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			var discoveryErr error
			oidcProvider, discoveryErr = oidc.NewProvider(discoveryCtx, oidcCfg)
			cancel()
			if discoveryErr != nil {
				slog.Error("OIDC provider discovery failed", "error", discoveryErr)
			}
		}
	}
	_ = authmw.DefaultAuthConfig
	router := newRouter(logger, &cfg, cryptoWrapper, k8sClient, oidcProvider)

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
		slog.Info("starting api",
			"port", cfg.Port,
			"enable_decrypt", cfg.EnableDecrypt,
			"ready", cfg.Ready(),
			"cert_provider_configured", cfg.KubeSealCertURL != "",
		)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("server error", "error", err)
			stop()
		}
	}()

	<-ctx.Done()
	slog.Info("shutting down api")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		slog.Error("shutdown error", "error", err)
	}
}

// staticCertProvider is a placeholder that returns an error.
// Used when KUBESEAL_CERT_URL is not configured.
type staticCertProvider struct{}

func (s *staticCertProvider) Get(_ context.Context) (*x509.Certificate, error) {
	return nil, fmt.Errorf("cert provider not configured: set KUBESEAL_CERT_URL")
}

// devPrivateKey generates a deterministic RSA key for local development.
// NOT for production use.
func devPrivateKey() *rsa.PrivateKey {
	// This is a placeholder; Phase 2 will use the real controller key from K8s.
	// For Phase 1 dev we just need a valid key object to satisfy the interface.
	key, err := rsa.GenerateKey(nil, 2048)
	if err != nil {
		panic(fmt.Sprintf("devPrivateKey: generate key: %v", err))
	}
	return key
}
