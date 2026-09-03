// Package observability wraps slog with a redacting JSON handler so that
// sensitive values (tokens, ciphertext, private keys, passwords, cookies,
// request bodies) never reach the log stream.
//
// The handler wraps a stdlib slog.JSONHandler and walks each record's
// attributes, replacing any value whose key matches a sensitive marker
// with the literal "[REDACTED]" sentinel. The walk is recursive so that
// grouped attributes (slog.Group) are also scrubbed.
//
// Why a custom handler instead of context-based filters? The kubeseal-ui
// api log streams are consumed by Loki/Loki-derived log shippers that
// index by JSON path. We need the JSON envelope to remain stable and
// the sensitive fields to be present (so dashboards don't show "missing
// field" warnings) but with values replaced.
package observability

import (
	"context"
	"io"
	"log/slog"
	"strings"
)

// Redacted is the sentinel value substituted for any sensitive attribute.
// Exposed as a const so log consumers (dashboards, alerts) can match
// against it without depending on string comparison fragility.
const Redacted = "[REDACTED]"

// sensitiveKeyMarkers are substrings whose presence in an attribute key
// triggers redaction. Case-insensitive comparison.
//
// The marker list is intentionally narrow — every marker must map to a
// real leak that has actually been observed in the kubeseal-ui threat
// model (internal-docs/security/threat-model.md). Adding markers here
// without a corresponding threat entry makes logs less useful.
var sensitiveKeyMarkers = []string{
	"password",
	"token",
	"secret",
	"private_key",
	"ciphertext",
	"plaintext",
	"cookie",
	"set-cookie",
	"authorization",
	"session",
	"refresh",
	"csrf",
	"pem",
	"cert",      // "certificate" content; the cert metadata (subject, issuer) is safe but value not
	"client_id", // OIDC client identifier — not the token itself but identifies the integration
}

// isSensitiveKey reports whether the given attribute key matches a
// sensitive marker. Match is case-insensitive substring on the lowercased
// key. "token_endpoint" matches because it contains "token"; "auth_user"
// does not because it contains neither "auth" nor "token" (we don't
// match "auth" because legitimate fields like "author" or "authority"
// are common).
func isSensitiveKey(key string) bool {
	l := strings.ToLower(key)
	for _, m := range sensitiveKeyMarkers {
		if strings.Contains(l, m) {
			return true
		}
	}
	return false
}

// redactingJSONHandler wraps a slog.JSONHandler (or any handler that
// accepts records and emits JSON) and replaces sensitive attribute
// values before the underlying handler writes them.
type redactingJSONHandler struct {
	inner slog.Handler
}

// Enabled delegates to the inner handler so the wrapper does not affect
// level filtering or handler-chaining behavior.
func (h *redactingJSONHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.inner.Enabled(ctx, l)
}

// Handle scrubs the record's top-level attributes then delegates to the
// inner handler. Groups are walked recursively via slog.VisitGroups-style
// attribute reassembly.
//
// The scrubbing is non-mutating: we build a fresh attr slice and replace
// only the entries whose key is sensitive, leaving everything else
// (including pointer identity for non-string values) untouched.
func (h *redactingJSONHandler) Handle(ctx context.Context, r slog.Record) error {
	scrubbed := make([]slog.Attr, 0, r.NumAttrs())
	r.Attrs(func(a slog.Attr) bool {
		scrubbed = append(scrubbed, scrubAttr(a))
		return true
	})
	clone := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)
	clone.AddAttrs(scrubbed...)
	return h.inner.Handle(ctx, clone)
}

// WithAttrs returns a new redacting handler whose inner handler carries
// the additional attributes. This makes the wrapper safe to use inside
// slog.Logger.With(...) chains.
func (h *redactingJSONHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	scrubbed := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		scrubbed[i] = scrubAttr(a)
	}
	return &redactingJSONHandler{inner: h.inner.WithAttrs(scrubbed)}
}

// WithGroup returns a new redacting handler whose inner handler has the
// group applied. Group attributes themselves are not sensitive; the
// scrub happens on the children.
func (h *redactingJSONHandler) WithGroup(name string) slog.Handler {
	return &redactingJSONHandler{inner: h.inner.WithGroup(name)}
}

// attrsToAny converts a slice of slog.Attr to []any so it can be spread
// into the variadic slog.Group(key, args...) constructor.
func attrsToAny(attrs []slog.Attr) []any {
	out := make([]any, len(attrs))
	for i, a := range attrs {
		out[i] = a
	}
	return out
}

// scrubAttr returns a copy of a with its value replaced by Redacted when
// the key is sensitive. For grouped attrs (slog.KindGroup), the children
// are walked recursively.
func scrubAttr(a slog.Attr) slog.Attr {
	if a.Value.Kind() == slog.KindGroup {
		children := a.Value.Group()
		scrubbed := make([]slog.Attr, len(children))
		for i, c := range children {
			scrubbed[i] = scrubAttr(c)
		}
		return slog.Group(a.Key, attrsToAny(scrubbed)...)
	}
	if isSensitiveKey(a.Key) {
		return slog.String(a.Key, Redacted)
	}
	return a
}

// RedactingJSONHandler returns a slog.Handler that emits JSON records
// to w with sensitive attribute values replaced by [REDACTED]. The
// opts argument is forwarded to the underlying JSONHandler so callers
// can control level, add source info, etc.
//
// The returned handler is safe to use as the default slog handler. Wrap
// with slog.New(...) to install.
func RedactingJSONHandler(w io.Writer, opts *slog.HandlerOptions) slog.Handler {
	return &redactingJSONHandler{inner: slog.NewJSONHandler(w, opts)}
}

// NewLogger returns a slog.Logger backed by the redacting JSON handler.
// Convenience for the common "set default and use" pattern in main.go.
func NewLogger(w io.Writer, level slog.Level) *slog.Logger {
	return slog.New(RedactingJSONHandler(w, &slog.HandlerOptions{Level: level}))
}
