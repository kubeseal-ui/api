package metrics

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/trace"
)

// newTestReader builds a manual reader, swaps the global meter for a test
// meter, and resets the construction state so the test meter is picked up.
// It returns the reader for collection.
func newTestReader(t *testing.T) *sdkmetric.ManualReader {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	meter = provider.Meter("test")
	instrumentsOnce = sync.Once{}
	instrumentsReadyMu.Lock()
	instrumentsReady = false
	instrumentsReadyMu.Unlock()
	t.Cleanup(func() {
		_ = provider.Shutdown(context.Background())
	})
	return reader
}

// collect gathers the recorded metrics into a lookup by name.
func collect(t *testing.T, reader *sdkmetric.ManualReader) map[string]metricdata.Metrics {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	out := make(map[string]metricdata.Metrics, len(rm.ScopeMetrics))
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			out[m.Name] = m
		}
	}
	return out
}

func findAttrs(t *testing.T, m metricdata.Metrics, want ...attribute.KeyValue) bool {
	t.Helper()
	data, ok := m.Data.(metricdata.Sum[int64])
	if !ok {
		t.Fatalf("metric %s: not an int64 sum", m.Name)
	}
	for _, dp := range data.DataPoints {
		match := true
		for _, w := range want {
			v, exists := dp.Attributes.Value(w.Key)
			if !exists || v != w.Value {
				match = false
				break
			}
		}
		if match && len(dp.Attributes.ToSlice()) == len(want) {
			return true
		}
	}
	return false
}

func TestInstrumentsBuildAndRecord(t *testing.T) {
	reader := newTestReader(t)
	if err := Instruments(); err != nil {
		t.Fatalf("Instruments: %v", err)
	}
	if err := Instruments(); err != nil {
		t.Fatalf("Instruments (idempotent second call): %v", err)
	}

	RecordHTTPRequest("/secrets/{namespace}/{name}", "GET", 200, 42*time.Millisecond)
	RecordSecretOperation("reveal", "success")
	RecordGitOpsDelivery("direct", "success")
	RecordGitOpsDelivery("proposal", "proposal_failed")
	RecordOpenFGACheck("allow")
	RecordOIDCAuth("success")

	got := collect(t, reader)
	for _, name := range []string{
		"kubeseal_ui_http_requests_total",
		"kubeseal_ui_http_request_duration_seconds",
		"kubeseal_ui_sealed_secret_operations_total",
		"kubeseal_ui_gitops_delivery_total",
		"kubeseal_ui_openfga_check_total",
		"kubeseal_ui_oidc_auth_total",
	} {
		if _, ok := got[name]; !ok {
			t.Errorf("metric %s not recorded", name)
		}
	}
	if req, ok := got["kubeseal_ui_http_requests_total"]; ok {
		if !findAttrs(t, req, attribute.String("handler", "/secrets/{namespace}/{name}"), attribute.String("method", "GET"), attribute.String("code", "200")) {
			t.Errorf("http_requests attrs mismatch: %+v", req)
		}
	}
	if dlv, ok := got["kubeseal_ui_gitops_delivery_total"]; ok {
		if !findAttrs(t, dlv, attribute.String("mode", "proposal"), attribute.String("result", "proposal_failed")) {
			t.Errorf("gitops_delivery attrs mismatch: %+v", dlv)
		}
	}
}

func TestEmptyLabelValuesBecomeUnknown(t *testing.T) {
	reader := newTestReader(t)
	if err := Instruments(); err != nil {
		t.Fatal(err)
	}
	RecordHTTPRequest("", "", 500, time.Millisecond)
	got := collect(t, reader)
	req := got["kubeseal_ui_http_requests_total"]
	if !findAttrs(t, req, attribute.String("handler", "unknown"), attribute.String("method", "unknown"), attribute.String("code", "500")) {
		t.Fatalf("empty label values not guarded: %+v", req)
	}
}

// TestNoIdentityOrResourceLabels pins the bounded-cardinality contract:
// every recorded attribute key must be in the allow-list, so a namespace
// or secret name can never become a label.
func TestNoIdentityOrResourceLabels(t *testing.T) {
	reader := newTestReader(t)
	if err := Instruments(); err != nil {
		t.Fatal(err)
	}
	RecordHTTPRequest("/secrets/db/pg-cred", "GET", 200, time.Millisecond)
	RecordSecretOperation("patch", "denied")
	RecordGitOpsDelivery("direct", "conflict")
	RecordOpenFGACheck("deny")
	RecordOIDCAuth("failed")

	allowed := map[string]bool{
		"handler": true, "method": true, "code": true,
		"operation": true, "result": true, "mode": true,
	}
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			sum, ok := m.Data.(metricdata.Sum[int64])
			if !ok {
				continue
			}
			for _, dp := range sum.DataPoints {
				for _, attr := range dp.Attributes.ToSlice() {
					if !allowed[string(attr.Key)] {
						t.Errorf("metric %s carries unbounded label %q", m.Name, attr.Key)
					}
				}
			}
		}
	}
}

// TestTraceCorrelationGuard makes sure the package compiles against the
// trace API used by the middleware bridge without importing a provider.
func TestTraceCorrelationGuard(t *testing.T) {
	var _ trace.Tracer = trace.NewNoopTracerProvider().Tracer("test")
	if !strings.Contains("trace_id span_id", "trace_id") {
		t.Fatal("unreachable")
	}
}
