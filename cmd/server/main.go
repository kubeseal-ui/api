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
	"github.com/kubeseal-ui/api/internal/gitops"
	"github.com/kubeseal-ui/api/internal/kubernetes"
	"github.com/kubeseal-ui/api/internal/observability"
	"github.com/kubeseal-ui/api/internal/policy"
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

// discoverOIDC performs provider discovery when the OIDC environment is
// complete; incomplete or absent configuration returns nil and the router
// stays fail-closed.
func discoverOIDC(cfg *config.Config) *oidc.Provider {
	if cfg.OIDCIssuer == "" || cfg.OIDCClientID == "" {
		return nil
	}
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
		return nil
	}
	discoveryCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	provider, err := oidc.NewProvider(discoveryCtx, oidcCfg)
	if err != nil {
		slog.Error("OIDC provider discovery failed", "error", err)
		return nil
	}
	return provider
}

// gitopsTransport builds the production go-git transport and typed
// credential resolver from configuration. Returns nils when GitOps is
// disabled — the serving path then has no Git-backed editing, matching
// the fail-closed contract.
func gitopsTransport(cfg *config.Config) (gitops.GitTransport, error) {
	if !cfg.GitOpsEnabled {
		return nil, nil
	}
	resolver, err := gitops.NewFileCredentialResolver(parseCredentialRefs(cfg.GitCredentialRefs))
	if err != nil {
		return nil, err
	}
	worktreeDir := cfg.GitWorktreeDir
	if worktreeDir == "" {
		worktreeDir = "/tmp/kubeseal-ui/gitops"
	}
	transport, err := gitops.NewGoGitTransport(gitops.GoGitOptions{
		ScratchDir:  worktreeDir,
		AuthorName:  cfg.GitAuthorName,
		AuthorEmail: cfg.GitAuthorEmail,
		Credentials: resolver,
	})
	if err != nil {
		return nil, err
	}
	return transport, nil
}

// parseCredentialRefs parses the comma-separated typed credential list.
// Each entry is auth_ref:mode:username:token_file; empty usernames are
// allowed (the transport defaults them).
func parseCredentialRefs(raw string) []gitops.FileCredential {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var refs []gitops.FileCredential
	for _, entry := range strings.Split(raw, ",") {
		parts := strings.Split(strings.TrimSpace(entry), ":")
		if len(parts) < 2 {
			continue
		}
		ref := gitops.FileCredential{AuthRef: parts[0], Mode: gitops.AuthMode(strings.TrimSpace(parts[1]))}
		if len(parts) > 2 {
			ref.Username = parts[2]
		}
		if len(parts) > 3 {
			ref.TokenFile = parts[3]
		}
		refs = append(refs, ref)
	}
	return refs
}

// parseMappingSpecs parses the comma-separated namespace mapping list.
// Each entry is namespace:repo:branch:path_template:auth_ref:mode with an
// optional :adapter_name suffix for proposal mode; path templates use '-'
// in place of '/'.
func parseMappingSpecs(raw string) []policy.GitMappingSpec {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var specs []policy.GitMappingSpec
	for _, entry := range strings.Split(raw, ",") {
		parts := strings.Split(strings.TrimSpace(entry), ":")
		if len(parts) < 6 {
			continue
		}
		spec := policy.GitMappingSpec{
			Namespace:    parts[0],
			Repository:   parts[1],
			Branch:       parts[2],
			PathTemplate: strings.ReplaceAll(parts[3], "-", "/"),
			AuthRef:      parts[4],
			Mode:         policy.GitDeliveryMode(parts[5]),
		}
		if len(parts) > 6 {
			spec.ProposalAdapterName = parts[6]
		}
		specs = append(specs, spec)
	}
	return specs
}

// proposalAdapters returns the named host adapters available to
// values-driven seeding. The registry grows as concrete host adapters
// land; platform-agnostic delivery requires none.
func proposalAdapters() map[string]policy.ProposalAdapter {
	return map[string]policy.ProposalAdapter{}
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
	oidcProvider := discoverOIDC(&cfg)
	_ = authmw.DefaultAuthConfig
	transport, transportErr := gitopsTransport(&cfg)
	if transportErr != nil {
		slog.Error("gitops transport construction failed", "error", transportErr)
		os.Exit(1)
	}
	if transport != nil {
		slog.Info("gitops delivery enabled", "worktree_dir", cfg.GitWorktreeDir, "credentials", len(parseCredentialRefs(cfg.GitCredentialRefs)))
	}
	router, routerErr := newRouter(routerOptions{
		logger:       logger,
		cfg:          &cfg,
		crypto:       cryptoWrapper,
		k8s:          k8sClient,
		transport:    transport,
		oidcProvider: oidcProvider,
		mappingSpecs: parseMappingSpecs(cfg.GitMappingSpecs),
		adapters:     proposalAdapters(),
	})
	if routerErr != nil {
		slog.Error("router construction failed", "error", routerErr)
		os.Exit(1)
	}
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
