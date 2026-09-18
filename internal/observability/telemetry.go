// Package observability wires the OpenTelemetry SDK: metrics, traces, and
// logs, all exported over OTLP to a collector (Prometheus, Loki, and Tempo
// read from it). It is optional infrastructure: when no OTLP endpoint is
// configured the SDK stays unmounted, /metrics serves the Prometheus
// exporter alone, and logging falls back to plain slog with no trace
// attributes, so local and test boots never make network calls.
//
// Design decisions:
//
//   - One SDK, one protocol: go.opentelemetry.io/otel with OTLP gRPC for
//     all three signals. A single collector pipeline receives metrics,
//     traces, and logs; the frontend uses OTLP/HTTP separately.
//   - /metrics is a Prometheus text endpoint served by the OTel Prometheus
//     exporter on the main port. ServiceMonitor scrapes it; no separate
//     metrics port or admin route exists to misconfigure.
//   - W3C traceparent propagation: the HTTP middleware starts a server
//     span per request and the request logger adds trace_id/span_id, so
//     every log line correlates to a span and every metric (via exemplars)
//     back to a trace.
//   - Bounded labels: metric attributes carry handler, method, and status
//     code only. User identities, namespaces, and secret names are
//     excluded from metrics by construction (they belong in the security
//     events and logs), keeping cardinality bounded.
//   - Fail-open: OTLP exporter construction failure logs a warning and
//     disables telemetry rather than refusing to boot — observability must
//     never take the API down.
package observability

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/log/global"
	"go.opentelemetry.io/otel/propagation"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"
)

// Telemetry holds the mounted SDK providers. A nil pointer or nil field
// means that signal is disabled; every consumer guards on it.
type Telemetry struct {
	TracerProvider *sdktrace.TracerProvider
	LoggerProvider *sdklog.LoggerProvider
	MeterProvider  *sdkmetric.MeterProvider
	// MetricsEnabled reports whether /metrics can serve the Prometheus
	// exposition. It is false when the provider never mounted.
	MetricsEnabled bool
}

// TelemetryOptions configures the SDK wiring.
type TelemetryOptions struct {
	// Endpoint is the OTLP gRPC host:port (no scheme). Required for any
	// signal to be exported.
	Endpoint string
	// ServiceName and ServiceVersion land in the resource attributes.
	ServiceName    string
	ServiceVersion string
	// Environment is deployment.environment.
	Environment string
	// TraceSampleRatio is the parent-based sampler ratio (0..1).
	TraceSampleRatio float64
	// MetricInterval is the OTLP push interval; 0 means 30s.
	MetricInterval time.Duration
	// Logger is used for wiring diagnostics; may be nil.
	Logger *slog.Logger
}

// logf returns the options logger or the slog default.
func (o TelemetryOptions) logf(level slog.Level, msg string, args ...any) {
	if o.Logger != nil {
		o.Logger.Log(context.Background(), level, msg, args...)
		return
	}
	slog.Log(context.Background(), level, msg, args...)
}

// resourceAttributes builds the SDK resource. k8s.namespace.name is fixed
// to the namespace the API runs in by the chart; the deployment
// environment carries the rest.
func (o TelemetryOptions) resourceAttributes() (*resource.Resource, error) {
	return resource.Merge(resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName(o.ServiceName),
			semconv.ServiceVersion(o.ServiceVersion),
			// deployment.environment (the classic key) rather than
			// deployment.environment.name: the chart and dashboards key
			// on the classic attribute.
			attribute.String("deployment.environment", o.Environment),
			semconv.K8SNamespaceName("kubeseal-ui"),
		))
}

// SetupTelemetry builds the three signal providers and mounts them as the
// global OTel defaults. A signal without an endpoint stays disabled; an
// exporter construction failure disables that signal with a warning
// instead of failing the boot. Call Shutdown on process exit.
func SetupTelemetry(opts TelemetryOptions) (*Telemetry, error) {
	tel := &Telemetry{}
	if opts.ServiceName == "" {
		opts.ServiceName = "kubeseal-gui-api"
	}
	if opts.Environment == "" {
		opts.Environment = "production"
	}
	if opts.TraceSampleRatio <= 0 || opts.TraceSampleRatio > 1 {
		opts.TraceSampleRatio = 0.1
	}
	if opts.MetricInterval <= 0 {
		opts.MetricInterval = 30 * time.Second
	}
	if opts.Endpoint == "" {
		opts.logf(slog.LevelInfo, "telemetry disabled: no OTLP endpoint configured")
		return tel, nil
	}
	res, err := opts.resourceAttributes()
	if err != nil {
		return nil, fmt.Errorf("telemetry resource: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Traces: OTLP gRPC, parent-based sampling.
	traceExp, traceErr := otlptracegrpc.New(ctx, otlptracegrpc.WithEndpoint(opts.Endpoint), otlptracegrpc.WithInsecure())
	if traceErr != nil {
		opts.logf(slog.LevelWarn, "trace exporter unavailable, traces disabled", "error", traceErr)
	} else {
		tel.TracerProvider = sdktrace.NewTracerProvider(
			sdktrace.WithResource(res),
			sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(opts.TraceSampleRatio))),
			sdktrace.WithBatcher(traceExp),
		)
		otel.SetTracerProvider(tel.TracerProvider)
	}

	// Metrics: OTLP push + a Prometheus exporter served at /metrics.
	if meterErr := setupMetrics(tel, res, opts); meterErr != nil {
		opts.logf(slog.LevelWarn, "metric exporter unavailable, metrics disabled", "error", meterErr)
	}

	// Logs: OTLP gRPC. The global logger provider backs the bridge the
	// request logger uses to add trace correlation.
	logExp, logErr := otlploggrpc.New(ctx, otlploggrpc.WithEndpoint(opts.Endpoint), otlploggrpc.WithInsecure())
	if logErr != nil {
		opts.logf(slog.LevelWarn, "log exporter unavailable, OTLP logs disabled", "error", logErr)
	} else {
		tel.LoggerProvider = sdklog.NewLoggerProvider(
			sdklog.WithResource(res),
			sdklog.WithProcessor(sdklog.NewBatchProcessor(logExp)),
		)
		global.SetLoggerProvider(tel.LoggerProvider)
	}

	// W3C propagation end to end.
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	opts.logf(slog.LevelInfo, "telemetry enabled",
		"endpoint", opts.Endpoint,
		"traces", tel.TracerProvider != nil,
		"metrics", tel.MeterProvider != nil,
		"logs", tel.LoggerProvider != nil,
		"trace_sample_ratio", opts.TraceSampleRatio,
	)
	return tel, nil
}

// setupMetrics wires the OTLP push exporter and the Prometheus reader.
func setupMetrics(tel *Telemetry, res *resource.Resource, opts TelemetryOptions) error {
	pushExp, err := otlpmetricgrpc.New(context.Background(),
		otlpmetricgrpc.WithEndpoint(opts.Endpoint), otlpmetricgrpc.WithInsecure())
	if err != nil {
		return err
	}
	promExp, err := prometheus.New()
	if err != nil {
		if shutdownErr := pushExp.Shutdown(context.Background()); shutdownErr != nil {
			opts.logf(slog.LevelDebug, "push exporter shutdown after prometheus failure", "error", shutdownErr)
		}
		return err
	}
	tel.MeterProvider = sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(res),
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(pushExp, sdkmetric.WithInterval(opts.MetricInterval))),
		sdkmetric.WithReader(promExp),
	)
	otel.SetMeterProvider(tel.MeterProvider)
	tel.MetricsEnabled = true
	return nil
}

// MetricsHandler serves the Prometheus text exposition at /metrics. The
// Prometheus exporter registers its collector on the default registry at
// construction, so promhttp.Handler() gathers exactly the instruments the
// provider holds. The handler returns 503 with a short body when metrics
// are disabled so ServiceMonitor marks the target down instead of
// scraping an empty page silently.
func (t *Telemetry) MetricsHandler() http.Handler {
	if t == nil || !t.MetricsEnabled {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "metrics disabled: no meter provider", http.StatusServiceUnavailable)
		})
	}
	return promhttp.Handler()
}

// Shutdown flushes and stops every mounted provider. It is called once on
// process exit; individual provider errors are logged, never fatal.
func (t *Telemetry) Shutdown(ctx context.Context) {
	if t == nil {
		return
	}
	if t.TracerProvider != nil {
		if err := t.TracerProvider.Shutdown(ctx); err != nil {
			slog.Error("trace provider shutdown", "error", err)
		}
	}
	if t.MeterProvider != nil {
		if err := t.MeterProvider.Shutdown(ctx); err != nil {
			slog.Error("meter provider shutdown", "error", err)
		}
	}
	if t.LoggerProvider != nil {
		if err := t.LoggerProvider.Shutdown(ctx); err != nil {
			slog.Error("log provider shutdown", "error", err)
		}
	}
}
