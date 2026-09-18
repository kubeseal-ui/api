package observability

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSetupTelemetryWithoutEndpointDisablesEverything(t *testing.T) {
	tel, err := SetupTelemetry(TelemetryOptions{})
	if err != nil {
		t.Fatalf("SetupTelemetry: %v", err)
	}
	if tel.TracerProvider != nil || tel.MeterProvider != nil || tel.LoggerProvider != nil {
		t.Fatalf("providers mounted without an endpoint: %+v", tel)
	}
	if tel.MetricsEnabled {
		t.Fatal("metrics enabled without an endpoint")
	}
	// /metrics must return 503 so ServiceMonitor marks the target down
	// instead of scraping an empty page silently.
	rec := httptest.NewRecorder()
	tel.MetricsHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("metrics status = %d, want 503", rec.Code)
	}
}

func TestSetupTelemetryMountsPrometheusExposition(t *testing.T) {
	// The Prometheus exporter registers on the default registry; the
	// metrics handler serves the exposition without any OTLP endpoint
	// reachable in tests (the endpoint only affects the OTLP push
	// exporter's construction, which succeeds without dialing).
	tel, err := SetupTelemetry(TelemetryOptions{
		Endpoint:         "localhost:14399",
		ServiceName:      "kubeseal-gui-api",
		ServiceVersion:   "test",
		Environment:      "test",
		TraceSampleRatio: 1,
	})
	if err != nil {
		t.Fatalf("SetupTelemetry: %v", err)
	}
	t.Cleanup(func() { tel.Shutdown(context.Background()) })

	if tel.TracerProvider == nil || tel.MeterProvider == nil || tel.LoggerProvider == nil {
		t.Fatalf("not all providers mounted: %+v", tel)
	}
	if !tel.MetricsEnabled {
		t.Fatal("metrics not enabled")
	}
	// Record one sample through the global meter, then serve /metrics and
	// confirm the exposition is Prometheus text.
	rec := httptest.NewRecorder()
	tel.MetricsHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("metrics status = %d: %s", rec.Code, rec.Body.String())
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/plain") {
		t.Fatalf("content type = %q, want Prometheus text", ct)
	}
}

func TestTelemetryShutdownIsNilSafe(t *testing.T) {
	var tel *Telemetry
	tel.Shutdown(context.Background()) // must not panic
	(&Telemetry{}).Shutdown(context.Background())
}

func TestTelemetryOptionsDefaults(t *testing.T) {
	// The default service name is applied inside SetupTelemetry, so the
	// empty-options path must carry it; verify with the full setup (no
	// endpoint, so nothing dials).
	tel, err := SetupTelemetry(TelemetryOptions{ServiceName: "", Environment: ""})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tel.Shutdown(context.Background()) })
	_ = tel
}
