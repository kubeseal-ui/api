// Package config loads kubeseal-ui/api runtime configuration from
// process flags and environment variables, validates the values, and
// provides a redacted String() representation suitable for startup
// logging.
//
// The Load() entry point is the single source of truth for what the
// api reads from its environment. Tests in config_test.go pin the
// defaults, the env override precedence, and the redaction contract.
// main.go consumes only the returned Config struct; nothing else in
// the codebase should reach into os.Getenv for configuration values.
//
// Why a package instead of inlining into main.go? Three reasons:
//
//  1. Testability — flag + env parsing has many edge cases (invalid
//     values, empty values, precedence); each needs a unit test. A
//     package boundary is the only sane place to host them.
//  2. Reuse — handlers, middleware, and certprovider all need config
//     values; passing the parsed struct avoids each having to re-parse.
//  3. Redaction — the String() method's redaction behavior is part of
//     the phase-1 security contract. Centralising it makes it auditable.
package config

import (
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
)

// Config holds the parsed runtime configuration for the kubeseal-ui api.
//
// Field tags document each value's source. The struct is passed by
// value to consumers that only need a few fields; consumers that
// mutate it must take a copy.
type Config struct {
	// Port is the TCP port the api binds to. Default 8080.
	// Sources: -port flag, KUBESEAL_API_PORT env.
	Port int

	// LogLevel is the slog level. One of: debug, info, warn, error.
	// Sources: -log-level flag, LOG_LEVEL env. Default "info".
	LogLevel string

	// OIDCIssuer is the OIDC provider URL (Authentik in production).
	// Non-secret per the threat model. Required for readiness.
	// Sources: OIDC_ISSUER env.
	OIDCIssuer string

	// OIDCClientID is the kubeseal-ui OAuth client id registered with
	// the provider. SECRET — must not appear in logs or error envelopes.
	// Sources: OIDC_CLIENT_ID env.
	OIDCClientID      string
	OIDCClientSecret  string
	OIDCRedirectURL   string
	OIDCScopes        string
	OIDCGroupsClaim   string
	OIDCUsernameClaim string

	// SessionSigningKey signs application session cookies. Required when
	// authenticated routes are enabled; never log this value.
	SessionSigningKey string

	// EnableDecrypt controls whether the decrypt endpoint and the
	// controller-private-key RBAC are wired. Phase-1 default is false.
	// Sources: ENABLE_DECRYPT env (must be literal "true" to enable).
	EnableDecrypt bool

	// KubeSealCertURL is the HTTP endpoint for fetching the controller
	// public certificate. Required for encryption.
	// Sources: -cert-url flag, KUBESEAL_CERT_URL env.
	KubeSealCertURL string

	// FakeK8sClient controls whether to use the fake Kubernetes client
	// for development. Default true.
	// Sources: -fake-k8s flag, FAKE_K8S_CLIENT env.
	FakeK8sClient       bool
	ControllerNamespace string
	ActiveKeyLabel      string
}

// Load parses configuration from process flags + environment and returns
// the validated Config. It never panics; errors are returned so callers
// can decide how to surface them (main.go exits, handlers retry, etc.).
//
// Flag registration happens at package init so the global flag set is
// defined only once per process — calling Load() multiple times (notably
// from tests) would otherwise panic with "flag redefined".
func Load() (Config, error) {
	cfg := Config{
		Port:                *flagPort,
		LogLevel:            *flagLevel,
		OIDCIssuer:          os.Getenv("OIDC_ISSUER"),
		OIDCClientID:        os.Getenv("OIDC_CLIENT_ID"),
		OIDCClientSecret:    os.Getenv("OIDC_CLIENT_SECRET"),
		OIDCRedirectURL:     os.Getenv("OIDC_REDIRECT_URL"),
		OIDCScopes:          os.Getenv("OIDC_SCOPES"),
		OIDCGroupsClaim:     os.Getenv("OIDC_GROUPS_CLAIM"),
		OIDCUsernameClaim:   os.Getenv("OIDC_USERNAME_CLAIM"),
		SessionSigningKey:   os.Getenv("SESSION_SIGNING_KEY"),
		EnableDecrypt:       os.Getenv("ENABLE_DECRYPT") == "true",
		KubeSealCertURL:     *flagCertURL,
		FakeK8sClient:       *flagFakeK8s,
		ControllerNamespace: os.Getenv("KUBESEAL_CONTROLLER_NAMESPACE"),
		ActiveKeyLabel:      os.Getenv("KUBESEAL_ACTIVE_KEY_LABEL"),
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

// Ready reports whether the api has enough configuration to serve
// requests. Used by /readyz to gate kubelet traffic.
//
// Phase-1 contract: readiness requires OIDC issuer and client id to
// both be present. EnableDecrypt is intentionally NOT part of readiness
// — decryption is gated at request time (phase-2 auth + ACL) so that
// the api can boot in modes that only allow encryption or only allow
// authenticated reads.
func (c Config) Ready() bool {
	return c.OIDCIssuer != "" && c.OIDCClientID != ""
}

// String returns a redacted, human-readable representation of the config.
// Safe to log at startup. Fields whose names match a sensitive marker
// (per observability.sensitiveKeyMarkers) are replaced with the
// "[REDACTED]" sentinel.
//
// Issuer URLs are NOT secret per the kubeseal-ui threat model
// (internal-docs/security/threat-model.md) so they flow through. Client
// IDs and tokens MUST NOT appear in this output.
func (c Config) String() string {
	return fmt.Sprintf(
		"port=%d log_level=%s oidc_issuer=%s oidc_client_id=%s enable_decrypt=%t",
		c.Port, c.LogLevel, c.OIDCIssuer, redactValue("oidc_client_id", c.OIDCClientID), c.EnableDecrypt,
	)
}

// redactValue returns Redacted when the key matches a sensitive marker,
// otherwise the value unchanged. Local copy of observability's marker
// list so the config package can render safely without importing the
// observability package (which would create a circular dependency
// risk as observability grows).
func redactValue(key, value string) string {
	if value == "" {
		return ""
	}
	if isSensitiveKey(key) {
		return "[REDACTED]"
	}
	return value
}

// isSensitiveKey mirrors observability.isSensitiveKey. Kept in sync
// manually because Go's stdlib has no first-class way to share private
// helpers across packages without exporting them.
//
// If you add a marker here, add it to observability.sensitiveKeyMarkers
// too. The two lists must agree.
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
