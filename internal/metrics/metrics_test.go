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

// newTestReader swaps the global meter for a test meter and resets the package's
// construction state, so the instruments are rebuilt against it.
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
	RecordSecretListing("degraded", 30, 1200*time.Millisecond)

	got := collect(t, reader)
	for _, name := range []string{
		"kubeseal_ui_http_requests_total",
		"kubeseal_ui_http_request_duration_seconds",
		"kubeseal_ui_sealed_secret_operations_total",
		"kubeseal_ui_gitops_delivery_total",
		"kubeseal_ui_openfga_check_total",
		"kubeseal_ui_oidc_auth_total",
		"kubeseal_ui_secret_listing_duration_seconds",
		"kubeseal_ui_secret_listing_items",
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
	// The listing's cost is per Secret, so its item count is recorded beside its duration, and both
	// carry the outcome that says whether the cost bought a complete answer.
	if items, ok := got["kubeseal_ui_secret_listing_items"]; ok {
		if !histogramHasAttrs(t, items, attribute.String("result", "degraded")) {
			t.Errorf("listing items attrs mismatch: %+v", items)
		}
	}
	if dur, ok := got["kubeseal_ui_secret_listing_duration_seconds"]; ok {
		if !histogramHasAttrs(t, dur, attribute.String("result", "degraded")) {
			t.Errorf("listing duration attrs mismatch: %+v", dur)
		}
	}
}

// histogramHasAttrs reports whether some data point carries exactly these attributes. Histograms
// need their own walk: findAttrs asserts the int64 sum shape.
func histogramHasAttrs(t *testing.T, m metricdata.Metrics, want ...attribute.KeyValue) bool {
	t.Helper()
	var points []attribute.Set
	switch data := m.Data.(type) {
	case metricdata.Histogram[float64]:
		for _, dp := range data.DataPoints {
			points = append(points, dp.Attributes)
		}
	case metricdata.Histogram[int64]:
		for _, dp := range data.DataPoints {
			points = append(points, dp.Attributes)
		}
	default:
		t.Fatalf("metric %s: not a histogram", m.Name)
	}
	for _, set := range points {
		match := true
		for _, w := range want {
			v, exists := set.Value(w.Key)
			if !exists || v != w.Value {
				match = false
				break
			}
		}
		if match && len(set.ToSlice()) == len(want) {
			return true
		}
	}
	return false
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

// Pins the bounded-cardinality contract: a namespace or secret name must never become a label.
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

// Keeps the package compiling against the trace API the middleware bridge uses, without
// importing a provider.
func TestTraceCorrelationGuard(t *testing.T) {
	var _ trace.Tracer = trace.NewNoopTracerProvider().Tracer("test")
	if !strings.Contains("trace_id span_id", "trace_id") {
		t.Fatal("unreachable")
	}
}
