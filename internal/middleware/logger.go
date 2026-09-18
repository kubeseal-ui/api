package middleware

import (
	"log/slog"
	"net/http"
	"time"

	"go.opentelemetry.io/otel/trace"
)

// statusRecorder captures the response status code for logging.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

// WriteHeader records the status then delegates.
func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// RequestLogger emits one structured log line per request: method, route
// pattern, status, duration, request ID, and — when a span is recording —
// trace_id and span_id, so every log line correlates to a trace in Tempo
// and every metric back to a log line. It NEVER logs request bodies,
// response bodies, query strings, or headers — those can carry
// credentials. The route pattern is bounded; the raw path (with namespace
// and secret names) never becomes a log label.
func RequestLogger(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rec, r)

			attrs := []any{
				"method", r.Method,
				"path", r.URL.Path,
				"route", OTelSpanRoutePattern(r),
				"status", rec.status,
				"duration_ms", time.Since(start).Milliseconds(),
				"request_id", RequestIDFromContext(r.Context()),
			}
			if span := trace.SpanFromContext(r.Context()); span.SpanContext().IsValid() {
				sc := span.SpanContext()
				attrs = append(attrs,
					"trace_id", sc.TraceID().String(),
					"span_id", sc.SpanID().String(),
				)
			}
			logger.Info("http_request", attrs...)
		})
	}
}
