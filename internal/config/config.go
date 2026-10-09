// Package config loads the api's runtime configuration from flags and environment, validates it, and
// renders it redacted for startup logging. Load is the only reader of the environment.
package config

import (
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	Port int

	LogLevel string

	// OIDCIssuer is the OIDC provider URL. Non-secret per the threat model, so it
	// flows through String().
	OIDCIssuer string

	// OIDCClientID is the OAuth client id. SECRET: it must never appear in logs or
	// error envelopes.
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

	// GitOpsEnabled selects the go-git transport and policy-backed Git mappings; a
	// disabled boot serves only the in-memory transport.
	GitOpsEnabled bool

	GitAuthorName  string
	GitAuthorEmail string

	// GitWorktreeDir holds per-target go-git worktrees, defaulting to the mounted
	// emptyDir /tmp/kubeseal-ui/gitops.
	GitWorktreeDir string

	// GitCredentialRefs is a comma-separated list of
	// auth_ref:mode:username:token_file entries. Token files are read per call, so a
	// rotated Secret takes effect without a restart, and no token ever enters a
	// configuration value.
	GitCredentialRefs string

	// GitMappingSpecs is the comma-separated
	// namespace:repo:branch:path_template:auth_ref:mode[:adapter] mapping list, with
	// '-' standing in for '/' in path templates. Read only when GitOps is enabled.
	GitMappingSpecs string

	// GitOpsProposalAdapters is the name:type:token_file[:base_url] adapter list. A
	// mapping may only name an adapter listed here; an unlisted name fails startup,
	// and an empty list leaves proposal namespaces unserviceable while direct
	// delivery keeps working. Token files are read per call.
	GitOpsProposalAdapters string

	// ConfigPath is the Git-managed policy document holding role definitions and
	// group-to-role grants. Empty keeps the fallback where an OIDC group named after
	// a built-in role grants that role everywhere; set, the document is the policy
	// and that fallback is off. SIGHUP re-reads it.
	ConfigPath string

	// OTelEndpoint is the OTLP gRPC host:port, without a scheme. Empty disables the
	// SDK: /metrics serves 503, logs stay plain slog, and no network calls are made.
	OTelEndpoint string

	// OTelServiceName and OTelServiceVersion land in the resource attributes; the
	// version falls back to the build info.
	OTelServiceName    string
	OTelServiceVersion string

	OTelEnvironment string

	// OTelTraceSampleRatio is the parent-based trace sampling ratio (0, 1];
	// out-of-range or empty means 0.1.
	OTelTraceSampleRatio string

	// OTelMetricIntervalSeconds is the OTLP metrics push interval; out-of-range or
	// empty means 30.
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
	switch strings.ToLower(c.LogLevel) {
	case "debug", "info", "warn", "error":
		return nil
	default:
		return fmt.Errorf("invalid log level %q: must be one of debug, info, warn, error", c.LogLevel)
	}
}

// Ready reports whether the api has enough configuration to serve requests; /readyz
// uses it to gate kubelet traffic. EnableDecrypt is deliberately excluded — decryption
// is gated per request, so a boot that only encrypts or only reads can still be ready.
func (c Config) Ready() bool {
	return c.OIDCIssuer != "" && c.OIDCClientID != ""
}

// String renders the config for startup logging with every sensitive field replaced by
// "[REDACTED]" per observability.sensitiveKeyMarkers. Issuer URLs are not secret per the
// threat model, so they flow through.
func (c Config) String() string {
	return fmt.Sprintf(
		"port=%d log_level=%s oidc_issuer=%s oidc_client_id=%s enable_decrypt=%t",
		c.Port, c.LogLevel, c.OIDCIssuer, redactValue("oidc_client_id", c.OIDCClientID), c.EnableDecrypt,
	)
}

// redactValue duplicates observability's marker check so config can render safely
// without importing it.
func redactValue(key, value string) string {
	if value == "" {
		return ""
	}
	if isSensitiveKey(key) {
		return "[REDACTED]"
	}
	return value
}

// isSensitiveKey mirrors observability.isSensitiveKey; the two marker lists must be
// updated together.
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
