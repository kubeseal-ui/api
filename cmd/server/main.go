// Package main wires the kubeseal-ui api server: health endpoints and the authenticated API routes.
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
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"

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

// devPrivProvider is a development-only PrivateKeyProvider; production uses the Kubernetes-backed one.
type devPrivProvider struct {
	key *rsa.PrivateKey
}

func (d *devPrivProvider) PrivateKeys(_ context.Context) ([]*rsa.PrivateKey, error) {
	return []*rsa.PrivateKey{d.key}, nil
}

// discoverOIDC returns nil on incomplete or absent config, leaving the router fail-closed. Discovery
// itself is lazy: an issuer that is down at boot must not pin the API into a restart to recover.
func discoverOIDC(cfg *config.Config) oidc.AuthProvider {
	if cfg.OIDCIssuer == "" || cfg.OIDCClientID == "" {
		if cfg.OIDCIssuer != "" || cfg.OIDCClientID != "" {
			slog.Warn("OIDC partially configured; both OIDC_ISSUER and OIDC_CLIENT_ID are required",
				"has_issuer", cfg.OIDCIssuer != "",
				"has_client_id", cfg.OIDCClientID != "",
			)
		}
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
	return oidc.NewLazyProvider(oidcCfg)
}

// gitopsTransport builds the production transport and credential resolver; both nil when GitOps is disabled (fail-closed).
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
	// Process-lived cache: memoizes a branch pull so a drift-resolving listing does not re-fetch per Secret.
	return gitops.NewCachingTransport(transport, cfg.GitSnapshotTTL), nil
}

// parseCredentialRefs parses "auth_ref:mode:username:token_file" entries; empty usernames are allowed.
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

// parseMappingSpecs parses "namespace:repo:branch:path_template:auth_ref:mode[:adapter][:;allowed_paths]"; '-' renders as '/' in templates.
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
		pathTemplate := parts[3]
		if !strings.Contains(pathTemplate, "/") {
			pathTemplate = strings.ReplaceAll(pathTemplate, "-", "/")
		}
		spec := policy.GitMappingSpec{
			Namespace:    parts[0],
			Repository:   parts[1],
			Branch:       parts[2],
			PathTemplate: pathTemplate,
			AuthRef:      parts[4],
			Mode:         policy.GitDeliveryMode(parts[5]),
		}
		if spec.Mode == policy.GitDeliveryProposal {
			if len(parts) > 6 {
				spec.ProposalAdapterName = parts[6]
			}
			if len(parts) > 7 {
				spec.AllowedPaths = parseAllowedPaths(parts[7])
			}
		} else {
			if len(parts) > 6 {
				spec.AllowedPaths = parseAllowedPaths(parts[6])
			}
		}
		specs = append(specs, spec)
	}
	return specs
}

func parseAllowedPaths(raw string) []string {
	if raw == "" {
		return nil
	}
	var paths []string
	for _, p := range strings.Split(raw, ";") {
		p = strings.TrimSpace(p)
		if p != "" {
			paths = append(paths, p)
		}
	}
	return paths
}

// checkMappingCredentials refuses a boot whose mappings name a credential GITOPS_CREDENTIAL_REFS does not define.
func checkMappingCredentials(specs []policy.GitMappingSpec, refs []gitops.FileCredential) error {
	known := make(map[string]struct{}, len(refs))
	for _, ref := range refs {
		known[ref.AuthRef] = struct{}{}
	}
	for _, spec := range specs {
		if _, ok := known[spec.AuthRef]; !ok {
			return fmt.Errorf("namespace %q maps to git credential %q, which GITOPS_CREDENTIAL_REFS does not define", spec.Namespace, spec.AuthRef)
		}
	}
	return nil
}

// proposalAdapterSpec is one parsed GITOPS_PROPOSAL_ADAPTERS entry.
type proposalAdapterSpec struct {
	Name      string
	Type      string
	TokenFile string
	BaseURL   string
}

// parseProposalAdapterSpecs parses "name:type:token_file[:base_url]" entries; malformed or duplicate entries fail closed.
func parseProposalAdapterSpecs(raw string) ([]proposalAdapterSpec, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	var specs []proposalAdapterSpec
	seen := map[string]struct{}{}
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		// SplitN with a limit of 4 keeps colons inside the base URL (https://host/path) intact.
		parts := strings.SplitN(entry, ":", 4)
		if len(parts) < 3 {
			return nil, fmt.Errorf("proposal adapter %q must be name:type:token_file[:base_url]", entry)
		}
		spec := proposalAdapterSpec{Name: strings.TrimSpace(parts[0]), Type: strings.TrimSpace(parts[1]), TokenFile: strings.TrimSpace(parts[2])}
		if len(parts) == 4 {
			spec.BaseURL = strings.TrimSpace(parts[3])
		}
		if spec.Name == "" || spec.Type == "" || spec.TokenFile == "" {
			return nil, fmt.Errorf("proposal adapter %q requires a name, a type, and a token file", entry)
		}
		if _, dup := seen[spec.Name]; dup {
			return nil, fmt.Errorf("duplicate proposal adapter name %q", spec.Name)
		}
		seen[spec.Name] = struct{}{}
		specs = append(specs, spec)
	}
	return specs, nil
}

// proposalAdapters builds the named adapters; a mapping referencing an unknown adapter fails the boot.
func proposalAdapters(cfg *config.Config) (map[string]gitops.ProposalProvider, error) {
	specs, err := parseProposalAdapterSpecs(cfg.GitOpsProposalAdapters)
	if err != nil {
		return nil, err
	}
	adapters := make(map[string]gitops.ProposalProvider, len(specs))
	for _, spec := range specs {
		switch spec.Type {
		case "github":
			provider, err := gitops.NewGitHubProposalProvider(gitops.GitHubProposalOptions{
				TokenFile: spec.TokenFile,
				BaseURL:   spec.BaseURL,
			})
			if err != nil {
				return nil, fmt.Errorf("proposal adapter %s: %w", spec.Name, err)
			}
			adapters[spec.Name] = provider
		default:
			return nil, fmt.Errorf("proposal adapter %s: unknown type %q", spec.Name, spec.Type)
		}
	}
	return adapters, nil
}

// setupTelemetryFromConfig is optional: no endpoint keeps /metrics at 503, and a setup failure logs a warning rather than exiting.
func setupTelemetryFromConfig(cfg *config.Config, logger *slog.Logger) *observability.Telemetry {
	version := cfg.OTelServiceVersion
	if version == "" {
		if info, ok := debug.ReadBuildInfo(); ok {
			version = info.Main.Version
		}
	}
	sampleRatio := 0.1
	if cfg.OTelTraceSampleRatio != "" {
		if parsed, parseErr := strconv.ParseFloat(cfg.OTelTraceSampleRatio, 64); parseErr == nil && parsed > 0 && parsed <= 1 {
			sampleRatio = parsed
		} else {
			slog.Warn("ignoring invalid OTEL_TRACE_SAMPLE_RATIO", "value", cfg.OTelTraceSampleRatio, "error", parseErr)
		}
	}
	metricInterval := 30 * time.Second
	if cfg.OTelMetricIntervalSeconds != "" {
		if parsed, parseErr := strconv.Atoi(cfg.OTelMetricIntervalSeconds); parseErr == nil && parsed > 0 {
			metricInterval = time.Duration(parsed) * time.Second
		} else {
			slog.Warn("ignoring invalid OTEL_METRIC_INTERVAL_SECONDS", "value", cfg.OTelMetricIntervalSeconds, "error", parseErr)
		}
	}
	telemetry, telemetryErr := observability.SetupTelemetry(observability.TelemetryOptions{
		Endpoint:         strings.TrimPrefix(cfg.OTelEndpoint, "http://"),
		ServiceName:      cfg.OTelServiceName,
		ServiceVersion:   version,
		Environment:      cfg.OTelEnvironment,
		TraceSampleRatio: sampleRatio,
		MetricInterval:   metricInterval,
		Logger:           logger,
	})
	if telemetryErr != nil {
		slog.Warn("telemetry setup failed; continuing without signals", "error", telemetryErr)
		return &observability.Telemetry{}
	}
	return telemetry
}

// buildKubernetesClient is fatal on cluster failure: the api cannot answer a single read without it.
func buildKubernetesClient(cfg config.Config) kubernetes.Client {
	if cfg.FakeK8sClient {
		return kubernetes.NewFake(
			[]kubernetes.Namespace{{Name: "default"}, {Name: "kube-system"}},
			[]kubernetes.SealedSecret{
				{Name: "example", Namespace: "default", Scope: "strict"},
			},
			nil,
		)
	}
	kubeConfig, err := rest.InClusterConfig()
	if err != nil {
		log.Fatal("kubernetes config", "error", err)
	}
	client, err := kubernetes.NewClientFromConfig(kubeConfig, kubernetes.Options{ControllerNamespace: cfg.ControllerNamespace, ActiveKeyLabel: cfg.ActiveKeyLabel})
	if err != nil {
		log.Fatal("kubernetes client", "error", err)
	}
	return client
}

// prewarmGitBranches pulls every mapped branch at boot, so the first request skips a cold clone.
func prewarmGitBranches(ctx context.Context, transport gitops.GitTransport, mappingSpecs []policy.GitMappingSpec, logger *slog.Logger) {
	if transport == nil || len(mappingSpecs) == 0 {
		return
	}
	warmTargets := make([]gitops.WarmTarget, 0, len(mappingSpecs))
	for _, spec := range mappingSpecs {
		warmTargets = append(warmTargets, gitops.WarmTarget{Repository: spec.Repository, Branch: spec.Branch, AuthRef: spec.AuthRef})
	}
	go gitops.PrewarmBranches(ctx, transport, warmTargets, logger)
}

func main() {
	flag.Parse()
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "config: %v\n", err)
		os.Exit(1)
	}

	version := loadVersion()
	printStartupBanner(version, cfg.Port)

	logger := observability.NewLogger(os.Stdout, slog.LevelInfo)
	slog.SetDefault(logger)

	// Telemetry: OTel SDK (metrics, traces, logs over OTLP).
	if cfg.OTelServiceVersion == "" {
		cfg.OTelServiceVersion = version
	}
	telemetry := setupTelemetryFromConfig(&cfg, logger)

	// Certificate provider (lazy fetch + TTL cache)
	var certProvider certprovider.Provider
	if cfg.KubeSealCertURL != "" {
		certProvider = certprovider.NewHTTP(certprovider.HTTPOptions{
			URL: cfg.KubeSealCertURL,
		})
	} else {
		slog.Warn("KUBESEAL_CERT_URL not set; encryption will fail until configured")
		certProvider = &staticCertProvider{}
	}

	// Kubernetes client (fake in explicit fake mode; production client otherwise)
	k8sClient := buildKubernetesClient(cfg)

	var privProvider crypto.PrivateKeyProvider
	if cfg.EnableDecrypt {
		if cfg.FakeK8sClient {
			privProvider = &devPrivProvider{key: devPrivateKey()}
		} else {
			privProvider = newKubePrivateKeyProvider(k8sClient, nil)
		}
	}
	cryptoWrapper := crypto.New(certProvider, privProvider)

	// Router with production middleware chain (request ID, recovery, timeout, logging).
	oidcProvider := discoverOIDC(&cfg)
	if cfg.OIDCIssuer != "" && cfg.SessionSigningKey == "" {
		slog.Error("SESSION_SIGNING_KEY is not configured while OIDC is enabled; /api/v1 routes will fail closed")
	}
	_ = authmw.DefaultAuthConfig
	transport, transportErr := gitopsTransport(&cfg)
	if transportErr != nil {
		slog.Error("gitops transport construction failed", "error", transportErr)
		os.Exit(1)
	}
	if transport != nil {
		slog.Info("gitops delivery enabled", "worktree_dir", cfg.GitWorktreeDir, "credentials", len(parseCredentialRefs(cfg.GitCredentialRefs)))
	}
	// Parsed once and reused: the boot check below and the router must see the same mappings.
	mappingSpecs := parseMappingSpecs(cfg.GitMappingSpecs)
	if cfg.GitOpsEnabled {
		if credentialErr := checkMappingCredentials(mappingSpecs, parseCredentialRefs(cfg.GitCredentialRefs)); credentialErr != nil {
			// Fail closed: a mapping whose credential does not exist can never deliver.
			slog.Error("gitops mapping references an undefined credential", "error", credentialErr)
			os.Exit(1)
		}
	}
	adapters, adaptersErr := proposalAdapters(&cfg)
	if adaptersErr != nil {
		slog.Error("proposal adapter construction failed", "error", adaptersErr)
		os.Exit(1)
	}

	// Built here so the SIGHUP loader below mutates the store the serving path reads from.
	policyStore := policy.NewPolicyStore()
	var policyLoader *policy.Loader
	if cfg.ConfigPath != "" {
		policyLoader, err = policy.NewLoader(cfg.ConfigPath, policyStore)
		if err != nil {
			// No valid generation exists yet, so there is nothing to fall back to.
			slog.Error("authorization policy load failed", "path", cfg.ConfigPath, "error", err)
			os.Exit(1)
		}
	} else {
		slog.Warn("CONFIG_PATH is not set; capabilities come from OIDC groups named after built-in roles, and group-to-role grants cannot be configured")
	}
	var readyCheck func() error
	if policyLoader != nil {
		readyCheck = policyLoader.Err
	}

	router, routerErr := newRouter(routerOptions{
		logger:         logger,
		cfg:            &cfg,
		crypto:         cryptoWrapper,
		k8s:            k8sClient,
		transport:      transport,
		oidcProvider:   oidcProvider,
		mappingSpecs:   mappingSpecs,
		adapters:       adapters,
		policyStore:    policyStore,
		readyCheck:     readyCheck,
		securityEvents: observability.NewStdoutSecurityEventSink(),
		metricsHandler: telemetry.MetricsHandler(),
	})
	if routerErr != nil {
		slog.Error("router construction failed", "error", routerErr)
		os.Exit(1)
	}
	// WriteTimeout must stay above the request deadline, or the response is severed mid-handler.
	const writeGrace = 15 * time.Second
	server := &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.Port),
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       cfg.APITimeout,
		WriteTimeout:      cfg.APITimeout + writeGrace,
		IdleTimeout:       60 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if policyLoader != nil {
		go watchPolicyReloads(ctx, policyLoader)
	}

	// Backgrounded: readiness must not block on a remote fetch.
	prewarmGitBranches(ctx, transport, mappingSpecs, logger)

	go func() {
		slog.Info("starting api",
			"version", version,
			"port", cfg.Port,
			"enable_decrypt", cfg.EnableDecrypt,
			"ready", cfg.Ready(),
			"cert_provider_configured", cfg.KubeSealCertURL != "",
			"config_path", cfg.ConfigPath,
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
	// Flush in-flight signals before exit so a rolling restart loses none.
	telemetry.Shutdown(shutdownCtx)
}

// watchPolicyReloads re-reads the policy document on SIGHUP; a failed reload keeps the last valid generation.
func watchPolicyReloads(ctx context.Context, loader *policy.Loader) {
	reloads := make(chan os.Signal, 1)
	signal.Notify(reloads, syscall.SIGHUP)
	defer signal.Stop(reloads)
	for {
		select {
		case <-ctx.Done():
			return
		case <-reloads:
			if err := loader.Reload(); err != nil {
				slog.Error("policy reload failed; keeping the last valid generation",
					"path", loader.Path(), "error", err)
				continue
			}
			slog.Info("policy reloaded", "path", loader.Path())
		}
	}
}

// staticCertProvider is the placeholder used when KUBESEAL_CERT_URL is not configured.
type staticCertProvider struct{}

func (s *staticCertProvider) Get(_ context.Context) (*x509.Certificate, error) {
	return nil, fmt.Errorf("cert provider not configured: set KUBESEAL_CERT_URL")
}

// loadVersion reads version.txt from the filesystem or falls back to build info / "dev".
func loadVersion() string {
	if content, err := os.ReadFile("version.txt"); err == nil {
		if v := strings.TrimSpace(string(content)); v != "" {
			return v
		}
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return "dev"
}

func printStartupBanner(version string, port int) {
	banner := `
  _  ___   _ ___ ___ ___ ___   _   _       _   ___ ___ 
 | |/ / | | | _ ) __/ __| __| /_\ | |     /_\ | _ \_ _|
 | ' <| |_| | _ \ _|\__ \ _| / _ \| |__  / _ \|  _/| | 
 |_|\_\\___/|___/___|___/___/_/ \_\____|/_/ \_\_| |___|

`
	fmt.Print(banner)
	fmt.Printf("Kubeseal UI API Server  •  Version: %s  •  Port: :%d\n\n", version, port)
}

// devPrivateKey generates an RSA key for local development. NOT for production use.
func devPrivateKey() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(nil, 2048)
	if err != nil {
		panic(fmt.Sprintf("devPrivateKey: generate key: %v", err))
	}
	return key
}
