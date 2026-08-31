package config

import (
	"strings"
	"testing"
)

// TestLoadDefaults documents the documented defaults when neither flags
// nor env vars are set. The values are the contract for "what does the
// kubeseal-ui api do with no configuration".
func TestLoadDefaults(t *testing.T) {
	t.Setenv("KUBESEAL_API_PORT", "")
	t.Setenv("LOG_LEVEL", "")
	t.Setenv("OIDC_ISSUER", "")
	t.Setenv("OIDC_CLIENT_ID", "")
	t.Setenv("ENABLE_DECRYPT", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Port != 8080 {
		t.Errorf("Port: want 8080, got %d", cfg.Port)
	}
	if cfg.LogLevel != "info" {
		t.Errorf("LogLevel: want info, got %q", cfg.LogLevel)
	}
	if cfg.OIDCIssuer != "" {
		t.Errorf("OIDCIssuer: want empty, got %q", cfg.OIDCIssuer)
	}
	if cfg.EnableDecrypt {
		t.Errorf("EnableDecrypt: want false, got true")
	}
}

// TestLoadFromEnv confirms env vars override the defaults. Flag values
// are tested separately in TestLoadFromFlags.
func TestLoadFromEnv(t *testing.T) {
	t.Setenv("KUBESEAL_API_PORT", "9090")
	t.Setenv("LOG_LEVEL", "debug")
	t.Setenv("OIDC_ISSUER", "https://auth.example.com")
	t.Setenv("OIDC_CLIENT_ID", "kubeseal-ui")
	t.Setenv("ENABLE_DECRYPT", "true")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Port != 9090 {
		t.Errorf("Port: want 9090, got %d", cfg.Port)
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("LogLevel: want debug, got %q", cfg.LogLevel)
	}
	if cfg.OIDCIssuer != "https://auth.example.com" {
		t.Errorf("OIDCIssuer: want https://auth.example.com, got %q", cfg.OIDCIssuer)
	}
	if cfg.OIDCClientID != "kubeseal-ui" {
		t.Errorf("OIDCClientID: want kubeseal-ui, got %q", cfg.OIDCClientID)
	}
	if !cfg.EnableDecrypt {
		t.Errorf("EnableDecrypt: want true, got false")
	}
}

// TestLoadInvalidPortEnvIgnored documents the env-validation contract:
// malformed port values fall back to the default (8080) rather than
// silently zeroing the port. Regression test for the errcheck finding
// in commit 27dc91b.
func TestLoadInvalidPortEnvIgnored(t *testing.T) {
	t.Setenv("KUBESEAL_API_PORT", "not-a-number")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Port != 8080 {
		t.Errorf("Port: want 8080 fallback, got %d", cfg.Port)
	}
}

// TestLoadUnknownLogLevelRejected documents that unrecognised log levels
// fail closed at load time. The server should never start with an
// invalid log level — better to refuse and let an operator fix the
// config than to silently log at default level.
func TestLoadUnknownLogLevelRejected(t *testing.T) {
	t.Setenv("LOG_LEVEL", "loud")

	_, err := Load()
	if err == nil {
		t.Fatal("expected Load to reject unknown log level")
	}
	if !strings.Contains(err.Error(), "log level") {
		t.Errorf("expected error to mention 'log level', got: %v", err)
	}
}

// TestReadyRequiresOIDC documents the readiness contract from
// phase-1.md: the api is ready when OIDC issuer + client id are both
// configured. Until they are, /readyz must report not_ready so kubelet
// does not route traffic.
func TestReadyRequiresOIDC(t *testing.T) {
	t.Setenv("OIDC_ISSUER", "")
	t.Setenv("OIDC_CLIENT_ID", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Ready() {
		t.Errorf("Ready: want false (no OIDC), got true")
	}
}

// TestReadyWithOIDC confirms readiness flips true once both OIDC values
// are present. EnableDecrypt is intentionally NOT part of readiness —
// decryption is gated at request time, not at startup.
func TestReadyWithOIDC(t *testing.T) {
	t.Setenv("OIDC_ISSUER", "https://auth.example.com")
	t.Setenv("OIDC_CLIENT_ID", "kubeseal-ui")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.Ready() {
		t.Errorf("Ready: want true (OIDC configured), got false")
	}
}

// TestStringRedactsSecrets is the regression test for the phase-1
// "no plaintext, ciphertext, token, cookie, PEM, or body leakage in
// logs and errors" requirement. The String method is what main.go uses
// to log the loaded config at startup; if it ever leaks a secret value,
// the test must fail.
func TestStringRedactsSecrets(t *testing.T) {
	t.Setenv("OIDC_ISSUER", "https://auth.example.com")
	t.Setenv("OIDC_CLIENT_ID", "super-secret-client-id")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	out := cfg.String()
	if strings.Contains(out, "super-secret-client-id") {
		t.Errorf("OIDCClientID leaked in String output: %s", out)
	}
	// Issuer is not a secret per the kubeseal-ui threat model
	// (internal-docs/security/threat-model.md) so it must flow through.
	if !strings.Contains(out, "https://auth.example.com") {
		t.Errorf("OIDCIssuer unexpectedly redacted: %s", out)
	}
}
