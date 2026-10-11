package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

// spanTracerProvider installs a recording provider as the GLOBAL OTel provider, as
// SetupTelemetry does at boot, and restores the previous one on cleanup.
func spanTracerProvider(t *testing.T) (*tracetest.SpanRecorder, func()) {
	t.Helper()
	recorder := tracetest.NewSpanRecorder()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	previous := otel.GetTracerProvider()
	otel.SetTracerProvider(provider)
	restore := func() {
		otel.SetTracerProvider(previous)
		_ = provider.Shutdown(context.Background())
	}
	t.Cleanup(restore)
	return recorder, restore
}

func TestOTelSpanCreatesRecordingSpan(t *testing.T) {
	recorder, _ := spanTracerProvider(t)

	handler := OTelSpan(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		span := trace.SpanFromContext(r.Context())
		if !span.IsRecording() {
			t.Fatal("request span is not recording")
		}
		if got := span.SpanContext().TraceID().String(); got == "" {
			t.Fatal("no trace id")
		}
	}))

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	handler.ServeHTTP(httptest.NewRecorder(), req)

	spans := recorder.Ended()
	if len(spans) != 1 {
		t.Fatalf("ended spans = %d, want 1", len(spans))
	}
	var route string
	for _, attr := range spans[0].Attributes() {
		if attr.Key == attribute.Key("http.route") {
			route = attr.Value.AsString()
		}
	}
	if route != "/healthz" {
		t.Fatalf("http.route = %q, want /healthz", route)
	}
	if kind := spans[0].SpanKind(); kind != trace.SpanKindServer {
		t.Fatalf("span kind = %v, want server", kind)
	}
}

func TestOTelSpanRecordsStatusOnSpan(t *testing.T) {
	recorder, _ := spanTracerProvider(t)

	handler := OTelSpan(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/readyz", nil))

	spans := recorder.Ended()
	if len(spans) != 1 {
		t.Fatalf("ended spans = %d", len(spans))
	}
	var status int
	var errored bool
	for _, attr := range spans[0].Attributes() {
		switch attr.Key {
		case attribute.Key("http.response.status_code"):
			status = int(attr.Value.AsInt64())
		case attribute.Key("error"):
			errored = attr.Value.AsBool()
		}
	}
	if status != http.StatusServiceUnavailable {
		t.Fatalf("status attribute = %d, want 503", status)
	}
	if !errored {
		t.Fatal("5xx did not mark the span as error")
	}
}

func TestOTelSpanRoutePatternFallsBackConservatively(t *testing.T) {
	// Resource-shaped segments collapse to "unmatched" so namespace and secret names never
	// become labels. This is the fallback for a request no route claimed; a matched route is
	// labelled from the router's own table, which the tests below cover.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/secrets/db/pg-cred", nil)
	if got := OTelSpanRoutePattern(req); got != "unmatched" {
		t.Fatalf("route pattern = %q, want unmatched", got)
	}
	req = httptest.NewRequest(http.MethodGet, "/healthz", nil)
	if got := OTelSpanRoutePattern(req); got != "/healthz" {
		t.Fatalf("route pattern = %q, want /healthz", got)
	}
}

// TestSetRoutePatternLabelsMatchedRoute uses the mount shape production uses — the protected routes
// sit behind mounted sub-routers, and chi installs a fresh route context for each. A flat router
// would pass even if the nested one reported a mount's pattern instead of the leaf route's, which is
// the failure this middleware exists to prevent, so the router below is nested as cmd/server builds
// it. Whether the accumulated pattern keeps the mount prefix is chi's business; that it is the leaf
// pattern rather than the raw path is ours, and -v prints which shape came back.
func TestSetRoutePatternLabelsMatchedRoute(t *testing.T) {
	router := chi.NewRouter()
	router.Route("/api/v1", func(api chi.Router) {
		api.Route("/", func(r chi.Router) {
			r.Group(func(r chi.Router) {
				r.Use(SetRoutePattern)
				r.Get("/secrets/{namespace}/{name}", func(http.ResponseWriter, *http.Request) {})
			})
		})
	})

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	RouteRecorder(RequestLogger(logger)(router)).
		ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/v1/secrets/db/pg-cred", nil))

	var line map[string]any
	if err := json.Unmarshal(buf.Bytes(), &line); err != nil {
		t.Fatalf("log line is not JSON: %v (%s)", err, buf.String())
	}
	route, _ := line["route"].(string)
	t.Logf("route label = %q", route)
	if !strings.HasSuffix(route, "/secrets/{namespace}/{name}") {
		t.Fatalf("route label = %q, want the leaf pattern the router matched", route)
	}
	if strings.Contains(route, "pg-cred") || strings.Contains(route, "db") {
		t.Fatalf("route label leaked the resource name: %q", route)
	}
	// The raw path stays on the line under its own key, deliberately: it is what names the Secret a
	// slow or failing request touched. Bounded cardinality is the label's requirement and the metric
	// takes `route` — internal/metrics/TestNoIdentityOrResourceLabels pins that no resource becomes a
	// label — so a stricter assertion here would trade attribution away for nothing.
	if path, _ := line["path"].(string); path != "/api/v1/secrets/db/pg-cred" {
		t.Fatalf("path = %q, want the raw path kept for attribution", path)
	}
}

func TestOTelSpanNameAndRouteUseMatchedPattern(t *testing.T) {
	recorder, _ := spanTracerProvider(t)

	// Nested the way cmd/server mounts the protected routes, for the reason the log test above gives.
	router := chi.NewRouter()
	router.Route("/api/v1", func(api chi.Router) {
		api.Route("/", func(r chi.Router) {
			r.Group(func(r chi.Router) {
				r.Use(SetRoutePattern)
				r.Get("/secrets/{namespace}/{name}", func(http.ResponseWriter, *http.Request) {})
			})
		})
	})
	RouteRecorder(OTelSpan(router)).
		ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/v1/secrets/db/pg-cred", nil))

	spans := recorder.Ended()
	if len(spans) != 1 {
		t.Fatalf("ended spans = %d, want 1", len(spans))
	}
	// Renamed from the holder after the route matched: a name is fixed at Start, so without the
	// rename the trace would carry the fallback's guess while the log carried the real route.
	name := spans[0].Name()
	if !strings.HasPrefix(name, "HTTP GET ") || !strings.HasSuffix(name, "/secrets/{namespace}/{name}") {
		t.Fatalf("span name = %q, want the matched pattern", name)
	}
	var routes []string
	for _, attr := range spans[0].Attributes() {
		if attr.Key == attribute.Key("http.route") {
			routes = append(routes, attr.Value.AsString())
		}
	}
	// Exactly one, and the matched pattern: a value written at start would leave a stale second.
	if len(routes) != 1 || !strings.HasSuffix(routes[0], "/secrets/{namespace}/{name}") {
		t.Fatalf("http.route attributes = %v, want the matched pattern once", routes)
	}
}

func TestOTelSpanExtractsInboundTraceparent(t *testing.T) {
	recorder, _ := spanTracerProvider(t)

	// The global propagator is a no-op until SetupTelemetry installs W3C TraceContext at
	// boot; the test mirrors that.
	previousProp := otel.GetTextMapPropagator()
	otel.SetTextMapPropagator(propagation.TraceContext{})
	t.Cleanup(func() { otel.SetTextMapPropagator(previousProp) })

	handler := OTelSpan(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Header.Set("traceparent", "00-11111111111111111111111111111111-2222222222222222-01")
	handler.ServeHTTP(httptest.NewRecorder(), req)

	spans := recorder.Ended()
	if len(spans) != 1 {
		t.Fatalf("ended spans = %d", len(spans))
	}
	if got := spans[0].SpanContext().TraceID().String(); got != "11111111111111111111111111111111" {
		t.Fatalf("trace id = %q, want the inbound traceparent id", got)
	}
}

func TestRequestLoggerAddsTraceCorrelation(t *testing.T) {
	_, _ = spanTracerProvider(t)

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	chain := OTelSpan(RequestLogger(logger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})))
	chain.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/healthz", nil))

	out := buf.String()
	if !strings.Contains(out, `"trace_id":"`) || !strings.Contains(out, `"span_id":"`) {
		t.Fatalf("log line missing trace correlation: %s", out)
	}
	if !strings.Contains(out, `"route":"/healthz"`) {
		t.Fatalf("route not recorded: %s", out)
	}
	if strings.Contains(out, "authorization") || strings.Contains(out, "cookie") {
		t.Fatalf("log line carries sensitive headers: %s", out)
	}
}

func TestRequestLoggerWithoutSpanHasNoTraceFields(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	chain := RequestLogger(logger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	chain.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/healthz", nil))

	out := buf.String()
	if strings.Contains(out, "trace_id") || strings.Contains(out, "span_id") {
		t.Fatalf("trace fields present without a span: %s", out)
	}
}

func TestPathHasVariableSegments(t *testing.T) {
	cases := map[string]bool{
		"/healthz":                  false,
		"/readyz":                   false,
		"/metrics":                  false,
		"/api/v1/secrets":           false,
		"/api/v1/secrets/db":        false,
		"/api/v1/secrets/db/pg":     true,
		"/api/v1/secrets/db/pg/key": true,
	}
	for path, want := range cases {
		if got := pathHasVariableSegments(path); got != want {
			t.Errorf("pathHasVariableSegments(%q) = %v, want %v", path, got, want)
		}
	}
}
