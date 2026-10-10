// Package observability mounts the OpenTelemetry SDK: metrics, traces and logs, all over
// OTLP gRPC to a collector. It is optional — with no endpoint configured the SDK stays
// unmounted, /metrics serves the Prometheus exporter alone, and logging falls back to plain
// slog. An exporter construction failure disables that signal rather than the boot.
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
	"go.opentelemetry.io/otel/propagation"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"
)

// Telemetry holds the mounted SDK providers; a nil field means that signal is disabled.
type Telemetry struct {
	TracerProvider *sdktrace.TracerProvider
	LoggerProvider *sdklog.LoggerProvider
	MeterProvider  *sdkmetric.MeterProvider
	MetricsEnabled bool
	logger         *slog.Logger
}

type TelemetryOptions struct {
	// Endpoint is the OTLP gRPC host:port, without a scheme. Empty disables every signal.
	Endpoint         string
	ServiceName      string
	ServiceVersion   string
	Environment      string
	TraceSampleRatio float64
	// MetricInterval is the OTLP push interval; 0 selects the 30s default.
	MetricInterval time.Duration
	// ExportTimeout bounds an OTLP export; 0 leaves the SDK default.
	ExportTimeout time.Duration
	// Logger carries wiring diagnostics and may be nil.
	Logger *slog.Logger
}

func (o TelemetryOptions) logf(level slog.Level, msg string, args ...any) {
	if o.Logger != nil {
		o.Logger.Log(context.Background(), level, msg, args...)
		return
	}
	slog.Log(context.Background(), level, msg, args...)
}

func (o TelemetryOptions) resourceAttributes() (*resource.Resource, error) {
	return resource.Merge(resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName(o.ServiceName),
			semconv.ServiceVersion(o.ServiceVersion),
			// deployment.environment (the classic key), not deployment.environment.name:
			// the chart and the dashboards key on the classic attribute.
			attribute.String("deployment.environment", o.Environment),
			semconv.K8SNamespaceName("kubeseal-ui"),
		))
}

// SetupTelemetry builds the three signal providers and mounts them as the global OTel
// defaults. A failed exporter disables that signal with a warning instead of failing the
// boot. Call Shutdown on process exit.
func SetupTelemetry(opts TelemetryOptions) (*Telemetry, error) {
	tel := &Telemetry{logger: opts.Logger}
	if opts.ServiceName == "" {
		opts.ServiceName = "kubeseal-ui-api"
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

	if meterErr := setupMetrics(tel, res, opts); meterErr != nil {
		opts.logf(slog.LevelWarn, "metric exporter unavailable, metrics disabled", "error", meterErr)
	}

	// The global logger provider backs the bridge the request logger uses for correlation.
	logExp, logErr := otlploggrpc.New(ctx, otlploggrpc.WithEndpoint(opts.Endpoint), otlploggrpc.WithInsecure())
	if logErr != nil {
		opts.logf(slog.LevelWarn, "log exporter unavailable, OTLP logs disabled", "error", logErr)
	} else {
		tel.LoggerProvider = sdklog.NewLoggerProvider(
			sdklog.WithResource(res),
			sdklog.WithProcessor(sdklog.NewBatchProcessor(logExp)),
		)
		otel.SetLoggerProvider(tel.LoggerProvider)
	}

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

func setupMetrics(tel *Telemetry, res *resource.Resource, opts TelemetryOptions) error {
	var grpcOpts []otlpmetricgrpc.Option
	grpcOpts = append(grpcOpts, otlpmetricgrpc.WithEndpoint(opts.Endpoint), otlpmetricgrpc.WithInsecure())
	if opts.ExportTimeout > 0 {
		grpcOpts = append(grpcOpts, otlpmetricgrpc.WithTimeout(opts.ExportTimeout))
	}
	pushExp, err := otlpmetricgrpc.New(context.Background(), grpcOpts...)
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

// MetricsHandler serves the Prometheus text exposition at /metrics, and answers 503 when
// metrics are disabled so ServiceMonitor marks the target down rather than scraping an
// empty page silently.
func (t *Telemetry) MetricsHandler() http.Handler {
	if t == nil || !t.MetricsEnabled {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "metrics disabled: no meter provider", http.StatusServiceUnavailable)
		})
	}
	return promhttp.Handler()
}

func (t *Telemetry) Shutdown(ctx context.Context) {
	if t == nil {
		return
	}
	// Bound shutdown flush so an unreachable collector never hangs process exit or tests indefinitely.
	shutdownCtx := ctx
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		shutdownCtx, cancel = context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
	}
	if t.TracerProvider != nil {
		if err := t.TracerProvider.Shutdown(shutdownCtx); err != nil {
			t.logWarn("trace provider shutdown", err)
		}
	}
	if t.MeterProvider != nil {
		if err := t.MeterProvider.Shutdown(shutdownCtx); err != nil {
			t.logWarn("meter provider shutdown", err)
		}
	}
	if t.LoggerProvider != nil {
		if err := t.LoggerProvider.Shutdown(shutdownCtx); err != nil {
			t.logWarn("log provider shutdown", err)
		}
	}
}

func (t *Telemetry) logWarn(msg string, err error) {
	if t.logger != nil {
		t.logger.Warn(msg, "error", err)
		return
	}
	slog.Warn(msg, "error", err)
}
