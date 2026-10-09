// Every reveal, patch, direct delivery and proposal attempt writes one JSON security event
// to stdout, carrying the authorized identity and resource but never plaintext, ciphertext,
// tokens, cookies or URLs with credentials. It goes through the redacting handler.
package observability

import (
	"log/slog"
	"os"
)

// SecurityEvent is one bounded audit record for a sensitive operation. Secret is the
// SealedSecret name, emitted under the attribute key "resource" and never "secret": the
// redactor matches keys by substring, so a key named "secret" would blank every record.
type SecurityEvent struct {
	Operation string
	Subject   string
	Namespace string
	Secret    string
	Key       string
	Mode      string
	Result    string
	RequestID string
}

// eventAttrs renders the event under the stable kubeseal_security_event envelope, which
// Loki-derived consumers index by JSON path.
func (e SecurityEvent) eventAttrs() []any {
	return []any{
		slog.String("event", "kubeseal_security_event"),
		slog.String("operation", e.Operation),
		slog.String("subject", e.Subject),
		slog.String("namespace", e.Namespace),
		slog.String("resource", e.Secret),
		slog.String("key", e.Key),
		slog.String("mode", e.Mode),
		slog.String("result", e.Result),
		slog.String("request_id", e.RequestID),
	}
}

type StdoutSecurityEventSink struct {
	logger *slog.Logger
}

// NewStdoutSecurityEventSink builds the production handlers.SecurityEventSink over stdout.
// The level is forced to Info because a security event must emit at every outcome,
// whatever the application log level happens to be.
func NewStdoutSecurityEventSink() *StdoutSecurityEventSink {
	return &StdoutSecurityEventSink{logger: slog.New(RedactingJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))}
}

// EmitSecurityEvent never panics and never returns an error: a broken stdout drops the
// record rather than failing the request that produced it.
func (s *StdoutSecurityEventSink) EmitSecurityEvent(operation, subject, namespace, secret, key, mode, result, requestID string) {
	if s == nil || s.logger == nil {
		return
	}
	event := SecurityEvent{
		Operation: operation,
		Subject:   subject,
		Namespace: namespace,
		Secret:    secret,
		Key:       key,
		Mode:      mode,
		Result:    result,
		RequestID: requestID,
	}
	s.logger.Info("security event", event.eventAttrs()...)
}
