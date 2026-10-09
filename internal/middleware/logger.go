package middleware

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/kubeseal-ui/api/internal/metrics"
	"go.opentelemetry.io/otel/trace"
)

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// RequestLogger emits one structured line per request, with trace_id/span_id when a span is
// recording so a log line correlates to a trace in Tempo. It never logs bodies, query
// strings or headers — those can carry credentials — and labels the bounded route pattern,
// never the raw path, which holds namespace and secret names.
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

			metrics.RecordHTTPRequest(route, r.Method, rec.status, duration)
		})
	}
}
