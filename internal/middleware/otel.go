package middleware

import (
	"context"
	"net/http"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// requestTracer reads the global provider on every call. The global delegating provider
// binds late, so a tracer taken before SetupTelemetry still records once the SDK is
// installed — no cache, and safe to mount unconditionally.
func requestTracer() trace.Tracer {
	return otel.Tracer("github.com/kubeseal-ui/api")
}

type statusRecorderPair struct {
	http.ResponseWriter
	span trace.Span
}

func (r *statusRecorderPair) WriteHeader(code int) {
	r.span.SetAttributes(attribute.Int("http.response.status_code", code))
	if code >= 500 {
		r.span.SetAttributes(attribute.Bool("error", true))
	}
	r.ResponseWriter.WriteHeader(code)
}

// OTelSpan starts a server span per request and extracts an inbound traceparent so upstream
// callers correlate into this service. The span carries the bounded route pattern, never the
// raw path, so namespace and secret names never become span labels.
func OTelSpan(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := otel.GetTextMapPropagator().Extract(r.Context(), headerCarrier{header: r.Header})
		route := OTelSpanRoutePattern(r)
		ctx, span := requestTracer().Start(ctx, "HTTP "+r.Method+" "+route,
			trace.WithSpanKind(trace.SpanKindServer),
			trace.WithAttributes(
				attribute.String("http.request.method", r.Method),
				attribute.String("http.route", route),
				attribute.String("server.address", r.Host),
			))
		defer span.End()
		rec := &statusRecorderPair{ResponseWriter: w, span: span}
		next.ServeHTTP(rec, r.WithContext(ctx))
	})
}

// OTelSpanRoutePattern resolves the bounded route pattern: a chi pattern registered by the
// router wins, anything else parameterizable collapses to "unmatched" rather than leaking
// namespace or secret names into labels.
func OTelSpanRoutePattern(r *http.Request) string {
	if pattern, ok := r.Context().Value(routePatternKey).(string); ok && pattern != "" {
		return pattern
	}
	if pathHasVariableSegments(r.URL.Path) {
		return "unmatched"
	}
	return r.URL.Path
}

type routePatternKeyType struct{}

var routePatternKey routePatternKeyType

func SetRoutePattern(pattern string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := contextWithRoutePattern(r.Context(), pattern)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

type headerCarrier struct{ header http.Header }

func (c headerCarrier) Get(key string) string { return c.header.Get(key) }
func (c headerCarrier) Set(key, value string) { c.header.Set(key, value) }
func (c headerCarrier) Keys() []string {
	keys := make([]string, 0, len(c.header))
	for k := range c.header {
		keys = append(keys, k)
	}
	return keys
}

func contextWithRoutePattern(ctx context.Context, pattern string) context.Context {
	return context.WithValue(ctx, routePatternKey, pattern)
}

// pathHasVariableSegments guesses whether a raw path carries resource identifiers without the
// router's pattern table: a segment of 32+ bytes, or one name deeper than the fixed
// /api/v1/<group> vocabulary, means it does.
func pathHasVariableSegments(path string) bool {
	segments := nonEmptySegments(path)
	if len(segments) == 0 {
		return false
	}
	root := segments[0]
	for i, seg := range segments {
		if len(seg) >= 32 {
			return true
		}
		// One name deeper than the fixed /api/v1/<group> vocabulary is the resource name.
		if root == "api" && i >= 4 {
			return true
		}
		if root == "secrets" && i >= 2 {
			return true
		}
	}
	return false
}

func nonEmptySegments(path string) []string {
	all := splitSegments(path)
	segs := make([]string, 0, len(all))
	for _, seg := range all {
		if seg != "" {
			segs = append(segs, seg)
		}
	}
	return segs
}

func splitSegments(path string) []string {
	var segs []string
	start := 0
	for i := 0; i < len(path); i++ {
		if path[i] == '/' {
			segs = append(segs, path[start:i])
			start = i + 1
		}
	}
	return append(segs, path[start:])
}
