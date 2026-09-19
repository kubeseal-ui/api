package middleware

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/kubeseal-ui/api/internal/metrics"
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
			duration := time.Since(start)
			route := OTelSpanRoutePattern(r)

			attrs := []any{
				"method", r.Method,
				"path", r.URL.Path,
				"route", route,
				"status", rec.status,
				"duration_ms", duration.Milliseconds(),
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

			// The RED metric is recorded with the same bounded route
			// pattern the log line carries, so rate/latency aggregate to
			// the handler and exemplars (when the collector supports
			// them) link back to the trace the log names.
			metrics.RecordHTTPRequest(route, r.Method, rec.status, duration)
		})
	}
}
