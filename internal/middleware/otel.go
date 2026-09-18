package middleware

import (
	"context"
	"net/http"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// requestTracer returns the tracer used for server spans. It reads the
// global provider on every call: the global delegating provider binds
// cheaply (a map lookup after the SDK is set) and supports late binding —
// a tracer obtained before SetupTelemetry starts producing recording spans
// once the SDK provider is installed — so no package-level once or cache
// is needed and the middleware is safe to mount unconditionally.
func requestTracer() trace.Tracer {
	return otel.Tracer("github.com/kubeseal-ui/api")
}

// statusRecorderPair pairs the response status with the request's span so
// the status code lands as a span attribute when the handler returns.
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

// OTelSpan starts a server span per request, extracts an inbound
// traceparent so upstream callers correlate into this service, records
// the bounded route attribute, and ends the span when the handler
// returns. The route pattern comes from OTelSpanRoutePattern, so
// namespace and secret names never become span labels.
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

// OTelSpanRoutePattern resolves the bounded route pattern for a request.
// A registered chi pattern (set by the router through SetRoutePattern)
// wins; anything else with a parameterizable shape collapses to
// "unmatched" rather than leaking namespace or secret names into labels.
func OTelSpanRoutePattern(r *http.Request) string {
	if pattern, ok := r.Context().Value(routePatternKey).(string); ok && pattern != "" {
		return pattern
	}
	if pathHasVariableSegments(r.URL.Path) {
		return "unmatched"
	}
	return r.URL.Path
}

// routePatternKey is the context key the router writes the matched
// pattern under.
type routePatternKeyType struct{}

var routePatternKey routePatternKeyType

// SetRoutePattern stores the matched route pattern in the request context.
// The router calls it from a tiny middleware; handlers and the span
// middleware read it via OTelSpanRoutePattern.
func SetRoutePattern(pattern string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := contextWithRoutePattern(r.Context(), pattern)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// headerCarrier adapts http.Header to the OTel TextMapCarrier.
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

// contextWithRoutePattern stores the pattern under routePatternKey.
func contextWithRoutePattern(ctx context.Context, pattern string) context.Context {
	return context.WithValue(ctx, routePatternKey, pattern)
}

// pathHasVariableSegments conservatively decides whether a raw path
// carries resource identifiers (namespace/secret names, UUIDs, long
// tokens). Without the router's pattern table, any segment of 32+ bytes
// or a deep api/secrets path is treated as parameterized and collapses
// to "unmatched".
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
		// /api/v1/<resource-group> is fixed vocabulary (namespaces,
		// secrets, gitops, auth, telemetry); one name deeper the
		// resource name appears and the path is no longer safe to
		// label.
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
