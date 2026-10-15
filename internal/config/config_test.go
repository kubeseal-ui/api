package config

import (
	"strings"
	"testing"
	"time"
)

func TestLoadDefaults(t *testing.T) {
	t.Setenv("KUBESEAL_API_PORT", "")
	t.Setenv("KUBESEAL_API_TIMEOUT_SECONDS", "")
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
	if cfg.APITimeout != DefaultAPITimeout {
		t.Errorf("APITimeout: want %s, got %s", DefaultAPITimeout, cfg.APITimeout)
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

// TestAPITimeout pins the documented bounds rather than a clamp: prd.md's Limits table says an
// invalid value fails startup, so a value outside the range must not be quietly rounded into it.
func TestAPITimeout(t *testing.T) {
	cases := map[string]struct {
		value   string
		want    time.Duration
		wantErr bool
	}{
		"unset keeps the documented default":   {"", DefaultAPITimeout, false},
		"override is honoured":                 {"45", 45 * time.Second, false},
		"the floor itself is accepted":         {"5", 5 * time.Second, false},
		"the hard maximum itself is accepted":  {"120", MaxAPITimeout, false},
		"below the floor fails startup":        {"4", 0, true},
		"above the hard maximum fails startup": {"121", 0, true},
		"zero fails startup":                   {"0", 0, true},
		"not a number fails startup":           {"thirty", 0, true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Setenv("KUBESEAL_API_TIMEOUT_SECONDS", tc.value)
			cfg, err := Load()
			if tc.wantErr {
				if err == nil {
					t.Fatalf("Load: want an error for %q, got timeout %s", tc.value, cfg.APITimeout)
				}
				return
			}
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if cfg.APITimeout != tc.want {
				t.Fatalf("APITimeout = %s, want %s", cfg.APITimeout, tc.want)
			}
		})
	}
}

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

func TestReadyWithOIDC(t *testing.T) {
	t.Setenv("OIDC_ISSUER", "https://auth.example.com")
	t.Setenv("OIDC_CLIENT_ID", "kubeseal-ui")
	t.Setenv("SESSION_SIGNING_KEY", "signing-key-for-test")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.Ready() {
		t.Errorf("Ready: want true (OIDC and signing key configured), got false")
	}
}

// A pod missing the signing key mounts no /api/v1 routes at all, so reporting ready would keep it in
// the Service endpoints while every API call 404s.
func TestReadyRequiresSessionSigningKey(t *testing.T) {
	t.Setenv("OIDC_ISSUER", "https://auth.example.com")
	t.Setenv("OIDC_CLIENT_ID", "kubeseal-ui")
	t.Setenv("SESSION_SIGNING_KEY", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Ready() {
		t.Errorf("Ready: want false (no session signing key), got true")
	}
}

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
	// The issuer is not a secret, so it must flow through.
	if !strings.Contains(out, "https://auth.example.com") {
		t.Errorf("OIDCIssuer unexpectedly redacted: %s", out)
	}
}
