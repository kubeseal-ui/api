// Package config loads the api's runtime configuration; Load is the only reader of the environment.
package config

import (
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	// Documented bounds from internal-docs/product/prd.md; out-of-range fails startup rather than clamping.
	DefaultAPITimeout = 30 * time.Second
	MaxAPITimeout     = 120 * time.Second
	// Floor below which the server could not answer even its own health checks.
	minAPITimeout = 5 * time.Second

	// Collapses a navigation burst into one pull per branch; the ceiling bounds staleness of advisory drift.
	DefaultGitSnapshotTTL = 15 * time.Second
	MaxGitSnapshotTTL     = 300 * time.Second
)

type Config struct {
	Port int

	// Bounds one request; the connection write deadline is deliberately set above it (see cmd/server).
	APITimeout time.Duration

	LogLevel string

	// OIDCIssuer is non-secret per the threat model, so it flows through String().
	OIDCIssuer string

	// SECRET: never in logs or error envelopes.
	OIDCClientID       string
	OIDCClientSecret   string
	OIDCRedirectURL    string
	OIDCScopes         string
	OIDCGroupsClaim    string
	OIDCUsernameClaim  string
	CookieDomain       string
	CSRFTrustedOrigins string

	// SessionSigningKey signs session cookies; never logged.
	SessionSigningKey string

	EnableDecrypt bool

	// KubeSealCertURL serves the controller public certificate; required for encryption.
	KubeSealCertURL string

	FakeK8sClient       bool
	ControllerNamespace string
	ActiveKeyLabel      string

	// Selects the go-git transport and policy-backed mappings; disabled serves only the in-memory transport.
	GitOpsEnabled bool

	GitAuthorName  string
	GitAuthorEmail string

	// Holds per-target go-git worktrees; defaults to the mounted emptyDir /tmp/kubeseal-ui/gitops.
	GitWorktreeDir string

	// Freshness window for the cross-request branch cache; drift is advisory, so staleness up to this bound is acceptable. Zero disables the cache.
	GitSnapshotTTL time.Duration

	// "auth_ref:mode:username:token_file" entries; token files read per call, so a rotated Secret needs no restart.
	GitCredentialRefs string

	// "namespace:repo:branch:path_template:auth_ref:mode[:adapter]" entries; '-' stands in for '/' in templates.
	GitMappingSpecs string

	// "name:type:token_file[:base_url]" adapter list; a mapping naming an unlisted adapter fails startup.
	GitOpsProposalAdapters string

	// Git-managed policy document; set, it is the sole grant source, and the OIDC group-name fallback is off.
	ConfigPath string

	// OTLP gRPC host:port, no scheme; empty disables the SDK entirely.
	OTelEndpoint string

	// Land in resource attributes; version falls back to build info.
	OTelServiceName    string
	OTelServiceVersion string

	OTelEnvironment string

	// Parent-based trace sampling ratio (0, 1]; out-of-range or empty means 0.1.
	OTelTraceSampleRatio string

	// OTLP metrics push interval in seconds; out-of-range or empty means 30.
	OTelMetricIntervalSeconds string
}

// Load parses flags and environment into a validated Config, returning errors rather than panicking.
func Load() (Config, error) {
	cfg := Config{
		Port:                      *flagPort,
		LogLevel:                  *flagLevel,
		OIDCIssuer:                os.Getenv("OIDC_ISSUER"),
		OIDCClientID:              os.Getenv("OIDC_CLIENT_ID"),
		OIDCClientSecret:          os.Getenv("OIDC_CLIENT_SECRET"),
		OIDCRedirectURL:           os.Getenv("OIDC_REDIRECT_URL"),
		OIDCScopes:                os.Getenv("OIDC_SCOPES"),
		OIDCGroupsClaim:           os.Getenv("OIDC_GROUPS_CLAIM"),
		OIDCUsernameClaim:         os.Getenv("OIDC_USERNAME_CLAIM"),
		CookieDomain:              os.Getenv("COOKIE_DOMAIN"),
		CSRFTrustedOrigins:        os.Getenv("CSRF_TRUSTED_ORIGINS"),
		SessionSigningKey:         os.Getenv("SESSION_SIGNING_KEY"),
		EnableDecrypt:             os.Getenv("ENABLE_DECRYPT") == "true",
		KubeSealCertURL:           *flagCertURL,
		FakeK8sClient:             *flagFakeK8s,
		ControllerNamespace:       os.Getenv("KUBESEAL_CONTROLLER_NAMESPACE"),
		ActiveKeyLabel:            os.Getenv("KUBESEAL_ACTIVE_KEY_LABEL"),
		GitOpsEnabled:             os.Getenv("GITOPS_ENABLED") == "true",
		GitAuthorName:             os.Getenv("GITOPS_AUTHOR_NAME"),
		GitAuthorEmail:            os.Getenv("GITOPS_AUTHOR_EMAIL"),
		GitWorktreeDir:            os.Getenv("GITOPS_WORKTREE_DIR"),
		GitCredentialRefs:         os.Getenv("GITOPS_CREDENTIAL_REFS"),
		GitMappingSpecs:           os.Getenv("GITOPS_NAMESPACES"),
		GitOpsProposalAdapters:    os.Getenv("GITOPS_PROPOSAL_ADAPTERS"),
		ConfigPath:                os.Getenv("CONFIG_PATH"),
		OTelEndpoint:              os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"),
		OTelServiceName:           os.Getenv("OTEL_SERVICE_NAME"),
		OTelServiceVersion:        os.Getenv("OTEL_SERVICE_VERSION"),
		OTelEnvironment:           os.Getenv("OTEL_DEPLOYMENT_ENVIRONMENT"),
		OTelTraceSampleRatio:      os.Getenv("OTEL_TRACE_SAMPLE_RATIO"),
		OTelMetricIntervalSeconds: os.Getenv("OTEL_METRIC_INTERVAL_SECONDS"),
	}

	// Default set before the override so an unset variable keeps it rather than zeroing every request.
	cfg.APITimeout = DefaultAPITimeout
	if v := os.Getenv("KUBESEAL_API_TIMEOUT_SECONDS"); v != "" {
		parsed, sErr := strconv.Atoi(v)
		if sErr != nil {
			return Config{}, fmt.Errorf("invalid KUBESEAL_API_TIMEOUT_SECONDS %q: not a number", v)
		}
		cfg.APITimeout = time.Duration(parsed) * time.Second
	}

	// Cache defaults on; explicit 0 disables it, so the variable is only read when set.
	cfg.GitSnapshotTTL = DefaultGitSnapshotTTL
	if v := os.Getenv("GITOPS_SNAPSHOT_TTL_SECONDS"); v != "" {
		parsed, sErr := strconv.Atoi(v)
		if sErr != nil || parsed < 0 {
			return Config{}, fmt.Errorf("invalid GITOPS_SNAPSHOT_TTL_SECONDS %q: must be a non-negative number", v)
		}
		cfg.GitSnapshotTTL = time.Duration(parsed) * time.Second
	}

	if v := os.Getenv("KUBESEAL_API_PORT"); v != "" {
		parsed, sErr := strconv.Atoi(v)
		if sErr != nil || parsed <= 0 || parsed > 65535 {
			slog.Warn("ignoring invalid KUBESEAL_API_PORT, using flag default",
				"value", v, "error", sErr)
		} else {
			cfg.Port = parsed
		}
	}

	if v := os.Getenv("LOG_LEVEL"); v != "" {
		cfg.LogLevel = v
	}

	if v := os.Getenv("KUBESEAL_CERT_URL"); v != "" {
		cfg.KubeSealCertURL = v
	}

	if v := os.Getenv("FAKE_K8S_CLIENT"); v != "" {
		cfg.FakeK8sClient = v == "true"
	}

	if err := cfg.validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) validate() error {
	if c.APITimeout < minAPITimeout || c.APITimeout > MaxAPITimeout {
		return fmt.Errorf("invalid API timeout %s: must be between %s and %s", c.APITimeout, minAPITimeout, MaxAPITimeout)
	}
	if c.GitSnapshotTTL < 0 || c.GitSnapshotTTL > MaxGitSnapshotTTL {
		return fmt.Errorf("invalid Git snapshot TTL %s: must be between 0 and %s", c.GitSnapshotTTL, MaxGitSnapshotTTL)
	}
	switch strings.ToLower(c.LogLevel) {
	case "debug", "info", "warn", "error":
		return nil
	default:
		return fmt.Errorf("invalid log level %q: must be one of debug, info, warn, error", c.LogLevel)
	}
}

// Ready gates /readyz; the signing key is included because a pod missing it mounts no /api/v1 routes at all, so readiness would keep a dead pod in the endpoints.
func (c Config) Ready() bool {
	return c.OIDCIssuer != "" && c.OIDCClientID != "" && c.SessionSigningKey != ""
}

// String renders startup logging with sensitive fields replaced by "[REDACTED]"; issuer URLs are not secret.
func (c Config) String() string {
	return fmt.Sprintf(
		"port=%d api_timeout=%s log_level=%s oidc_issuer=%s oidc_client_id=%s enable_decrypt=%t",
		c.Port, c.APITimeout, c.LogLevel, c.OIDCIssuer, redactValue("oidc_client_id", c.OIDCClientID), c.EnableDecrypt,
	)
}

// redactValue duplicates observability's marker check so config need not import it.
func redactValue(key, value string) string {
	if value == "" {
		return ""
	}
	if isSensitiveKey(key) {
		return "[REDACTED]"
	}
	return value
}

// isSensitiveKey mirrors observability.isSensitiveKey; the two marker lists must be updated together.
func isSensitiveKey(key string) bool {
	l := strings.ToLower(key)
	markers := []string{
		"password", "token", "secret", "private_key",
		"ciphertext", "plaintext", "cookie", "set-cookie",
		"authorization", "session", "refresh", "csrf",
		"pem", "cert", "client_id",
	}
	for _, m := range markers {
		if strings.Contains(l, m) {
			return true
		}
	}
	return false
}
