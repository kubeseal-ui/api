package middleware

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

// spanTracerProvider installs a recording provider as the GLOBAL OTel
// provider (what SetupTelemetry does at boot) and registers a span
// recorder so tests can assert on the spans the middleware ended. The
// previous provider is restored on cleanup.
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
	// A path with resource-shaped segments collapses to "unmatched" so
	// namespace and secret names never become labels.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/secrets/db/pg-cred", nil)
	if got := OTelSpanRoutePattern(req); got != "unmatched" {
		t.Fatalf("route pattern = %q, want unmatched", got)
	}
	// Fixed health paths keep the raw path.
	req = httptest.NewRequest(http.MethodGet, "/healthz", nil)
	if got := OTelSpanRoutePattern(req); got != "/healthz" {
		t.Fatalf("route pattern = %q, want /healthz", got)
	}
	// The router-provided pattern wins over the raw path.
	req = httptest.NewRequest(http.MethodGet, "/api/v1/secrets/db/pg-cred", nil)
	req = req.WithContext(contextWithRoutePattern(req.Context(), "/api/v1/secrets/{namespace}/{name}"))
	if got := OTelSpanRoutePattern(req); got != "/api/v1/secrets/{namespace}/{name}" {
		t.Fatalf("route pattern = %q, want the router pattern", got)
	}
}

func TestOTelSpanExtractsInboundTraceparent(t *testing.T) {
	recorder, _ := spanTracerProvider(t)

	// The global propagator defaults to no-op until SetupTelemetry
	// installs W3C TraceContext at boot; the test mirrors that.
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
	// Request headers never appear in the log line.
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
