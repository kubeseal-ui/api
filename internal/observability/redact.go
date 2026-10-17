// Package observability wraps slog with a redacting JSON handler: any attribute whose key matches a sensitive marker is
// written as the [REDACTED] sentinel, groups walked recursively; keys stay present because Loki consumers index by JSON path.
package observability

import (
	"context"
	"io"
	"log/slog"
	"strings"
)

// Redacted is the sentinel substituted for a sensitive value; consumers match it by name rather than a copied string.
const Redacted = "[REDACTED]"

// Substrings whose presence in a lowercased attribute key triggers redaction; every marker must map to a recorded leak, or logs lose signal.
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
	"cert",
	"client_id",
}

// Case-insensitive substring match; "auth" is deliberately absent, or author and authority would be redacted.
func isSensitiveKey(key string) bool {
	l := strings.ToLower(key)
	for _, m := range sensitiveKeyMarkers {
		if strings.Contains(l, m) {
			return true
		}
	}
	return false
}

type redactingJSONHandler struct {
	inner slog.Handler
}

func (h *redactingJSONHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.inner.Enabled(ctx, l)
}

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

func (h *redactingJSONHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	scrubbed := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		scrubbed[i] = scrubAttr(a)
	}
	return &redactingJSONHandler{inner: h.inner.WithAttrs(scrubbed)}
}

func (h *redactingJSONHandler) WithGroup(name string) slog.Handler {
	return &redactingJSONHandler{inner: h.inner.WithGroup(name)}
}

func attrsToAny(attrs []slog.Attr) []any {
	out := make([]any, len(attrs))
	for i, a := range attrs {
		out[i] = a
	}
	return out
}

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

// RedactingJSONHandler writes JSON to w with sensitive attribute values replaced by [REDACTED]; safe as the default slog handler.
func RedactingJSONHandler(w io.Writer, opts *slog.HandlerOptions) slog.Handler {
	return &redactingJSONHandler{inner: slog.NewJSONHandler(w, opts)}
}

func NewLogger(w io.Writer, level slog.Level) *slog.Logger {
	return slog.New(RedactingJSONHandler(w, &slog.HandlerOptions{Level: level}))
}
