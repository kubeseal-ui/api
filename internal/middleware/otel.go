package middleware

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"
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
		// The router matches further down the chain, so no pattern is known yet. The span is named
		// from the conservative fallback and corrected below once the request has been routed.
		ctx, span := requestTracer().Start(ctx, "HTTP "+r.Method+" "+OTelSpanRoutePattern(r),
			trace.WithSpanKind(trace.SpanKindServer),
			trace.WithAttributes(
				attribute.String("http.request.method", r.Method),
				attribute.String("server.address", r.Host),
			))
		defer span.End()
		rec := &statusRecorderPair{ResponseWriter: w, span: span}
		next.ServeHTTP(rec, r.WithContext(ctx))
		// Set once, here, rather than at start: a value set at start would leave the span carrying a
		// second, stale http.route beside the real one.
		route := OTelSpanRoutePattern(r)
		span.SetName("HTTP " + r.Method + " " + route)
		span.SetAttributes(attribute.String("http.route", route))
	})
}

// OTelSpanRoutePattern resolves the bounded route pattern: the pattern the router matched wins,
// anything else parameterizable collapses to "unmatched" rather than leaking namespace or secret
// names into labels.
func OTelSpanRoutePattern(r *http.Request) string {
	if holder, ok := r.Context().Value(routePatternKey).(*routePattern); ok && holder.pattern != "" {
		return holder.pattern
	}
	if pathHasVariableSegments(r.URL.Path) {
		return "unmatched"
	}
	return r.URL.Path
}

type routePatternKeyType struct{}

var routePatternKey routePatternKeyType

// routePattern is a holder rather than a value, which is the whole reason it exists. The pattern is
// only known once the router has matched, and every reader — the span, the log line, the metric —
// runs outside that moment. A context value set by inner middleware is invisible to outer
// middleware, and chi installs a fresh RouteContext for every mounted sub-router, so the outermost
// context carries the parent mux's pattern rather than the leaf route's. A pointer placed outermost
// and filled in by the route is the one shape that survives both.
type routePattern struct{ pattern string }

// RouteRecorder publishes the holder that the matched route fills in. Mount it outside the router's
// matching, before anything that reads the pattern.
func RouteRecorder(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), routePatternKey, &routePattern{})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// SetRoutePattern fills the holder from the router's own pattern table. Mount it on the routes
// themselves, where the pattern is known: a top-level middleware runs before matching, where chi has
// none. It reads the pattern rather than accepting one, so a route cannot be labelled with a pattern
// it does not serve.
func SetRoutePattern(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if pattern := chiRoutePattern(r); pattern != "" {
			if holder, ok := r.Context().Value(routePatternKey).(*routePattern); ok {
				holder.pattern = pattern
			}
		}
		next.ServeHTTP(w, r)
	})
}

// chiRoutePattern returns the pattern chi matched, or "" when nothing matched — which is also what a
// not-found request gets.
func chiRoutePattern(r *http.Request) string {
	if rc := chi.RouteContext(r.Context()); rc != nil {
		return rc.RoutePattern()
	}
	return ""
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
