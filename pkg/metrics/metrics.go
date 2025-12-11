package metrics

import (
	"context"
	"fmt"
	"os"
	"time"

	"go.opentelemetry.io/contrib/exporters/autoexport"
	"go.opentelemetry.io/otel/attribute"
	api "go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/sdk/metric"

	"github.com/italypaleale/le-cert-server/pkg/buildinfo"
	"github.com/italypaleale/le-cert-server/pkg/config"
)

const prefix = "lcs"

type AppMetrics struct {
	letsEncryptRequests api.Float64Histogram
	certRequests        api.Int64Counter
}

func NewAppMetrics(ctx context.Context) (m *AppMetrics, shutdownFn func(ctx context.Context) error, err error) {
	cfg := config.Get()

	m = &AppMetrics{}

	resource, err := cfg.GetOtelResource(buildinfo.AppName)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get OpenTelemetry resource: %w", err)
	}

	// Get the metric reader
	// If the env var OTEL_METRICS_EXPORTER is empty, we set it to "none"
	if os.Getenv("OTEL_METRICS_EXPORTER") == "" {
		_ = os.Setenv("OTEL_METRICS_EXPORTER", "none") //nolint:errcheck
	}
	mr, err := autoexport.NewMetricReader(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to initialize OpenTelemetry metric reader: %w", err)
	}

	mp := metric.NewMeterProvider(
		metric.WithResource(resource),
		metric.WithReader(mr),
	)
	meter := mp.Meter(prefix)

	m.certRequests, err = meter.Int64Counter(
		prefix+"_cert_requests",
		api.WithDescription("The number of certificate requests"),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create "+prefix+"_checks meter: %w", err)
	}

	m.letsEncryptRequests, err = meter.Float64Histogram(
		prefix+"_api_calls",
		api.WithDescription("Requests to Let's Encrypt and duration in seconds"),
		api.WithExplicitBucketBoundaries(1, 2, 5, 10, 20, 30, 45, 60, 90, 120, 180, 240, 300),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create "+prefix+"_api_calls meter: %w", err)
	}

	return m, mp.Shutdown, nil
}

//nolint:contextcheck
func (m *AppMetrics) RecordCertRequest(domain string, cached bool) {
	if m == nil {
		return
	}

	m.certRequests.Add(
		context.Background(),
		1,
		api.WithAttributeSet(
			attribute.NewSet(
				attribute.KeyValue{Key: "domain", Value: attribute.StringValue(domain)},
				attribute.KeyValue{Key: "cached", Value: attribute.BoolValue(cached)},
			),
		),
	)
}

//nolint:contextcheck
func (m *AppMetrics) RecordLetsEncryptRequests(duration time.Duration) {
	if m == nil {
		return
	}

	m.letsEncryptRequests.Record(
		context.Background(),
		float64(duration.Milliseconds())/1_000,
	)
}
