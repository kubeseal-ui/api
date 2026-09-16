// Stdout JSON security-event sink.
//
// The doc contract (architecture/git-delivery.md, architecture/api.md)
// requires every reveal, patch, direct delivery, and proposal attempt to
// write one JSON security event per attempt to stdout. Events carry
// authorized identity and resource fields but exclude plaintext,
// ciphertext, tokens, cookies, raw URLs with credentials, and diff
// bodies. The sink writes through the redacting slog handler so any
// attribute whose key matches a sensitive marker is dropped to
// [REDACTED] before it reaches the log stream.
package observability

import (
	"log/slog"
	"os"
)

// SecurityEvent is one bounded audit record for a sensitive operation.
// The fields mirror the handlers.SecurityEventSink contract; key values
// and diff bodies never appear here by construction.
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

// eventAttrs renders the event as slog attributes with a stable JSON
// envelope (kubeseal_security_event) so Loki-derived consumers can index
// by JSON path without missing-field warnings.
func (e SecurityEvent) eventAttrs() []any {
	return []any{
		slog.String("event", "kubeseal_security_event"),
		slog.String("operation", e.Operation),
		slog.String("subject", e.Subject),
		slog.String("namespace", e.Namespace),
		slog.String("secret", e.Secret),
		slog.String("key", e.Key),
		slog.String("mode", e.Mode),
		slog.String("result", e.Result),
		slog.String("request_id", e.RequestID),
	}
}

// StdoutSecurityEventSink writes security events to stdout through the
// redacting JSON handler. It is the production implementation of the
// handlers.SecurityEventSink contract.
type StdoutSecurityEventSink struct {
	logger *slog.Logger
}

// NewStdoutSecurityEventSink builds the sink over stdout. The redacting
// handler is reused so the [REDACTED] sentinel contract stays in one
// place; the level is forced to Info because security events must emit
// at every outcome regardless of the application log level.
func NewStdoutSecurityEventSink() *StdoutSecurityEventSink {
	return &StdoutSecurityEventSink{logger: slog.New(RedactingJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))}
}

// EmitSecurityEvent writes one event. It never panics and never returns
// an error: a broken stdout drops the record rather than failing the
// request that produced it.
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
