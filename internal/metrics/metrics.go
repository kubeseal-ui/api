// Package metrics defines the kubeseal-ui API's application metrics on
// top of the OTel meter API. Every instrument uses bounded attributes
// (handler, method, status code, operation, result): user identities,
// namespaces, and secret names are excluded from metrics by construction
// because they belong in the security events and logs, and unbounded
// label values are the fastest way to explode Prometheus cardinality.
//
// Metric names follow the observability contract
// (internal-docs/architecture/observability.md):
//
//	kubeseal_ui_http_requests_total{handler,method,code}
//	kubeseal_ui_http_request_duration_seconds{handler,method}
//	kubeseal_ui_sealed_secret_operations_total{operation,result}
//	kubeseal_ui_gitops_delivery_total{mode,result}
//	kubeseal_ui_openfga_check_total{result}
//	kubeseal_ui_oidc_auth_total{result}
package metrics

import (
	"context"
	"strconv"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

var (
	meter = otel.Meter("github.com/kubeseal-ui/api")

	httpRequests       metric.Int64Counter
	httpDuration       metric.Float64Histogram
	secretOperations   metric.Int64Counter
	gitopsDeliveries   metric.Int64Counter
	openFGAChecks      metric.Int64Counter
	oidcAuths          metric.Int64Counter
	instrumentsOnce    sync.Once
	instrumentsErr     error
	instrumentsReadyMu sync.RWMutex
	instrumentsReady   bool
)

// Instruments builds every counter and histogram once. It is safe to call
// repeatedly; the first error is remembered and returned, and a failed
// construction leaves every instrument nil so recording stays a no-op
// instead of panicking.
func Instruments() error {
	instrumentsReadyMu.RLock()
	if instrumentsReady {
		instrumentsReadyMu.RUnlock()
		return instrumentsErr
	}
	instrumentsReadyMu.RUnlock()

	instrumentsOnce.Do(func() {
		var err error
		if httpRequests, err = meter.Int64Counter("kubeseal_ui_http_requests_total",
			metric.WithDescription("HTTP requests per handler, method, and status code")); err != nil {
			instrumentsErr = err
			return
		}
		if httpDuration, err = meter.Float64Histogram("kubeseal_ui_http_request_duration_seconds",
			metric.WithDescription("HTTP request duration in seconds per handler and method"),
			metric.WithExplicitBucketBoundaries(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10)); err != nil {
			instrumentsErr = err
			return
		}
		if secretOperations, err = meter.Int64Counter("kubeseal_ui_sealed_secret_operations_total",
			metric.WithDescription("Sealed secret operations by operation and result")); err != nil {
			instrumentsErr = err
			return
		}
		if gitopsDeliveries, err = meter.Int64Counter("kubeseal_ui_gitops_delivery_total",
			metric.WithDescription("GitOps delivery attempts by mode and result")); err != nil {
			instrumentsErr = err
			return
		}
		if openFGAChecks, err = meter.Int64Counter("kubeseal_ui_openfga_check_total",
			metric.WithDescription("OpenFGA authorization checks by result")); err != nil {
			instrumentsErr = err
			return
		}
		if oidcAuths, err = meter.Int64Counter("kubeseal_ui_oidc_auth_total",
			metric.WithDescription("OIDC authentication outcomes by result")); err != nil {
			instrumentsErr = err
			return
		}
		instrumentsReadyMu.Lock()
		instrumentsReady = true
		instrumentsReadyMu.Unlock()
	})
	return instrumentsErr
}

// RecordHTTPRequest records one served request. handler is the route
// pattern (bounded), never the raw path: paths contain namespace and
// secret names and would explode cardinality.
func RecordHTTPRequest(handler, method string, status int, duration time.Duration) {
	if err := Instruments(); err != nil || httpRequests == nil {
		return
	}
	attrs := metric.WithAttributes(
		mustString("handler", handler),
		mustString("method", method),
		mustString("code", strconv.Itoa(status)),
	)
	httpRequests.Add(context.TODO(), 1, attrs)
	httpDuration.Record(context.TODO(), duration.Seconds(), metric.WithAttributes(
		mustString("handler", handler),
		mustString("method", method),
	))
}

// RecordSecretOperation records one seal, reveal, or patch outcome.
func RecordSecretOperation(operation, result string) {
	if err := Instruments(); err != nil || secretOperations == nil {
		return
	}
	secretOperations.Add(context.TODO(), 1, metric.WithAttributes(
		mustString("operation", operation),
		mustString("result", result),
	))
}

// RecordGitOpsDelivery records one delivery attempt. mode is the fixed
// namespace policy mode (direct | proposal); result is the bounded
// outcome (success | conflict | denied | failed | proposal_failed |
// proposal_unavailable).
func RecordGitOpsDelivery(mode, result string) {
	if err := Instruments(); err != nil || gitopsDeliveries == nil {
		return
	}
	gitopsDeliveries.Add(context.TODO(), 1, metric.WithAttributes(
		mustString("mode", mode),
		mustString("result", result),
	))
}

// RecordOpenFGACheck records one authorization check outcome.
func RecordOpenFGACheck(result string) {
	if err := Instruments(); err != nil || openFGAChecks == nil {
		return
	}
	openFGAChecks.Add(context.TODO(), 1, metric.WithAttributes(mustString("result", result)))
}

// RecordOIDCAuth records one authentication outcome (success | failed |
// callback_error | refresh).
func RecordOIDCAuth(result string) {
	if err := Instruments(); err != nil || oidcAuths == nil {
		return
	}
	oidcAuths.Add(context.TODO(), 1, metric.WithAttributes(mustString("result", result)))
}

// mustString guards an attribute value: an empty label value is legal but
// useless, so it becomes "unknown".
func mustString(key, value string) attribute.KeyValue {
	if value == "" {
		return attribute.String(key, "unknown")
	}
	return attribute.String(key, value)
}
