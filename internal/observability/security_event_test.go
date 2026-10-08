package observability

import (
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

func newTestSink() (*StdoutSecurityEventSink, *strings.Builder) {
	var out strings.Builder
	logger := slog.New(RedactingJSONHandler(&out, &slog.HandlerOptions{Level: slog.LevelInfo}))
	return &StdoutSecurityEventSink{logger: logger}, &out
}

func TestStdoutSecurityEventSinkEmitsBoundedJSON(t *testing.T) {
	sink, out := newTestSink()

	sink.EmitSecurityEvent("reveal", "user-1", "payments", "api-credentials", "password", "", "success", "req-1")

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
	if record["key"] != "password" {
		t.Fatalf("key name missing from event: %#v", record)
	}
	if record["result"] != "success" {
		t.Fatalf("result missing from event: %#v", record)
	}
}

// TestStdoutSecurityEventSinkPreservesResourceName guards a collision
// between the audit schema and the redactor: the redacting handler
// matches *attribute keys* by substring against markers that include
// "secret", so an event field literally named "secret" would ship as
// [REDACTED]. The resource name is the SealedSecret name, which is
// already public in the request path and in Kubernetes, and it is the
// one field an operator needs to answer "what was touched".
func TestStdoutSecurityEventSinkPreservesResourceName(t *testing.T) {
	sink, out := newTestSink()

	sink.EmitSecurityEvent("reveal", "user-1", "payments", "api-credentials", "password", "", "success", "req-1")

	var record map[string]any
	if err := json.Unmarshal([]byte(out.String()), &record); err != nil {
		t.Fatalf("event is not valid JSON: %v\n%s", err, out.String())
	}
	if record["resource"] != "api-credentials" {
		t.Fatalf("resource name = %v, want api-credentials", record["resource"])
	}
	for field, value := range record {
		if value == Redacted {
			t.Errorf("audit field %q was redacted; a security event carries no sensitive values", field)
		}
	}
}

// TestStdoutSecurityEventSinkStillRedactsSensitiveAttrs keeps the
// protection that matters: a caller that puts key material under a
// marked attribute key still gets the sentinel.
func TestStdoutSecurityEventSinkStillRedactsSensitiveAttrs(t *testing.T) {
	sink, out := newTestSink()

	sink.logger.Info("security event",
		slog.String("password", "hunter2"),
		slog.String("plaintext", "s3cr3t-value"),
		slog.String("request_id", "req-2"),
	)

	emitted := out.String()
	if !strings.Contains(emitted, Redacted) {
		t.Fatalf("sensitive keys not redacted: %s", emitted)
	}
	for _, leak := range []string{"hunter2", "s3cr3t-value"} {
		if strings.Contains(emitted, leak) {
			t.Fatalf("sensitive value %q leaked: %s", leak, emitted)
		}
	}
	// Non-sensitive fields keep flowing, or the event would be useless.
	if !strings.Contains(emitted, "req-2") {
		t.Fatalf("non-sensitive field dropped: %s", emitted)
	}
}

func TestNilSinkIsSafe(t *testing.T) {
	var sink *StdoutSecurityEventSink
	sink.EmitSecurityEvent("reveal", "u", "ns", "s", "", "", "denied", "r")
	// No panic is the contract: a broken sink never fails the request.
}
