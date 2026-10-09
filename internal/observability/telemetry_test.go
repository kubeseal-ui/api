package observability

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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
	rec := httptest.NewRecorder()
	tel.MetricsHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("metrics status = %d, want 503", rec.Code)
	}
}

func TestSetupTelemetryMountsPrometheusExposition(t *testing.T) {
	// The endpoint only affects the OTLP push exporter's construction, which succeeds
	// without dialing, so this mounts with no collector reachable.
	tel, err := SetupTelemetry(TelemetryOptions{
		Endpoint:         "localhost:14399",
		ServiceName:      "kubeseal-ui-api",
		ServiceVersion:   "test",
		Environment:      "test",
		TraceSampleRatio: 1,
		ExportTimeout:    50 * time.Millisecond,
		Logger:           slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatalf("SetupTelemetry: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		tel.Shutdown(ctx)
	})

	if tel.TracerProvider == nil || tel.MeterProvider == nil || tel.LoggerProvider == nil {
		t.Fatalf("not all providers mounted: %+v", tel)
	}
	if !tel.MetricsEnabled {
		t.Fatal("metrics not enabled")
	}
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
	tel, err := SetupTelemetry(TelemetryOptions{ServiceName: "", Environment: ""})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tel.Shutdown(context.Background()) })
	_ = tel
}
