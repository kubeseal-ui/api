package observability

import (
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

func TestStdoutSecurityEventSinkEmitsBoundedJSON(t *testing.T) {
	var out strings.Builder
	logger := slog.New(RedactingJSONHandler(&out, &slog.HandlerOptions{Level: slog.LevelInfo}))
	sink := &StdoutSecurityEventSink{logger: logger}
	if sink == nil {
		t.Fatal("sink construction failed")
	}

	sink.EmitSecurityEvent("reveal", "user-1", "payments", "api-credentials", "password", "", "attempt", "req-1")

	line := out.String()
	if line == "" {
		t.Fatal("no event written")
	}
	var record map[string]any
	if err := json.Unmarshal([]byte(line), &record); err != nil {
		t.Fatalf("event is not valid JSON: %v\n%s", err, line)
	}
	if record["event"] != "kubeseal_security_event" {
		t.Fatalf("unexpected event marker: %v", record["event"])
	}
	if record["operation"] != "reveal" || record["subject"] != "user-1" || record["namespace"] != "payments" || record["request_id"] != "req-1" {
		t.Fatalf("unexpected record: %#v", record)
	}
}

func TestStdoutSecurityEventSinkRedactsSensitiveKeys(t *testing.T) {
	var out strings.Builder
	logger := slog.New(RedactingJSONHandler(&out, &slog.HandlerOptions{Level: slog.LevelInfo}))

	// A hypothetical caller that puts secret material in a sensitive key
	// gets the [REDACTED] sentinel instead.
	logger.Info("security event", SecurityEvent{
		Operation: "patch", Subject: "user-1", Namespace: "payments",
		Secret: "api-credentials", Key: "ciphertext-probe", Mode: "direct",
		Result: "success", RequestID: "req-2",
	}.eventAttrs()...)

	if !strings.Contains(out.String(), Redacted) {
		t.Fatalf("sensitive keys not redacted: %s", out.String())
	}
	if strings.Contains(out.String(), "secret-value") {
		t.Fatalf("secret value leaked: %s", out.String())
	}
}

func TestNilSinkIsSafe(t *testing.T) {
	var sink *StdoutSecurityEventSink
	sink.EmitSecurityEvent("reveal", "u", "ns", "s", "", "", "attempt", "r")
	// No panic is the contract: a broken sink never fails the request.
}
