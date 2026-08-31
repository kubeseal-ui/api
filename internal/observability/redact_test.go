package observability

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// TestRedactReplacesSensitiveKeys documents the redaction contract:
// keys whose name contains a sensitive marker must have their values
// replaced with the literal "[REDACTED]" sentinel. The original value
// must NOT appear in the emitted log line. Regression test for the
// phase-1 "no plaintext, ciphertext, token, cookie, PEM, or body
// leakage in logs and errors" requirement.
func TestRedactReplacesSensitiveKeys(t *testing.T) {
	var buf bytes.Buffer
	h := RedactingJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	_ = slog.New(h)
	// Use the handler directly so we can attach attrs at known keys.
	rec := slog.NewRecord(time.Now(), slog.LevelInfo, "test", 0)
	rec.AddAttrs(
		slog.String("password", "hunter2"),
		slog.String("token", "eyJabc.def.ghi"),
		slog.String("client_secret", "shh"),
		slog.String("private_key", "-----BEGIN RSA PRIVATE KEY-----\nxyz\n-----END RSA PRIVATE KEY-----"),
		slog.String("ciphertext", "AgBxxxxxxxxxx"),
		slog.String("username", "alice"), // not sensitive
	)
	if err := h.Handle(context.Background(), rec); err != nil {
		t.Fatalf("handle: %v", err)
	}
	out := buf.String()
	for _, leak := range []string{"hunter2", "eyJabc.def.ghi", "shh", "BEGIN RSA PRIVATE KEY", "AgBxxxxxxxxxx"} {
		if strings.Contains(out, leak) {
			t.Errorf("redaction failed: %q present in log output: %s", leak, out)
		}
	}
	// Non-sensitive keys still flow through.
	if !strings.Contains(out, "alice") {
		t.Errorf("expected non-sensitive username to pass through; got: %s", out)
	}
	if !strings.Contains(out, "[REDACTED]") {
		t.Errorf("expected [REDACTED] sentinel; got: %s", out)
	}
}

// TestRedactPreservesJSONStructure ensures redaction does not break the
// JSON envelope that downstream log shippers rely on.
func TestRedactPreservesJSONStructure(t *testing.T) {
	var buf bytes.Buffer
	h := RedactingJSONHandler(&buf, nil)
	rec := slog.NewRecord(time.Now(), slog.LevelInfo, "msg", 0)
	rec.AddAttrs(slog.String("password", "secret"), slog.String("ok", "yes"))
	if err := h.Handle(context.Background(), rec); err != nil {
		t.Fatalf("handle: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &decoded); err != nil {
		t.Fatalf("output not valid JSON: %v\n%s", err, buf.String())
	}
	if decoded["password"] != "[REDACTED]" {
		t.Errorf("password field not redacted: %v", decoded["password"])
	}
	if decoded["ok"] != "yes" {
		t.Errorf("ok field was unexpectedly modified: %v", decoded["ok"])
	}
}
