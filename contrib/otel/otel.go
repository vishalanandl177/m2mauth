// Package otel provides OpenTelemetry integration for m2mauth.
//
// It implements authlog.EventHandler to emit OTel tracing spans and
// metric counters/histograms for all authentication operations.
//
// Usage:
//
//	import m2motel "github.com/vishalanandl177/m2mauth/contrib/otel"
//
//	handler := m2motel.NewEventHandler(
//	    m2motel.WithTracerProvider(tp),
//	    m2motel.WithMeterProvider(mp),
//	)
//
//	// Use with any m2mauth component:
//	auth, _ := oauth2.New(tokenURL, clientID,
//	    oauth2.WithEventHandler(handler),
//	)
package otel

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"

	"github.com/vishalanandl177/m2mauth/authlog"
)

const instrumentationName = "github.com/vishalanandl177/m2mauth/contrib/otel"

// EventHandler implements authlog.EventHandler with OpenTelemetry
// tracing and metrics instrumentation.
type EventHandler struct {
	tracer trace.Tracer
	meter  metric.Meter

	// Metrics instruments
	authTotal     metric.Int64Counter
	authDuration  metric.Float64Histogram
	tokenTotal    metric.Int64Counter
	tokenDuration metric.Float64Histogram
	certEvents    metric.Int64Counter
}

// Option configures the OTel EventHandler.
type Option func(*config)

type config struct {
	tracerProvider trace.TracerProvider
	meterProvider  metric.MeterProvider
}

// WithTracerProvider sets a custom TracerProvider. Defaults to the global provider.
func WithTracerProvider(tp trace.TracerProvider) Option {
	return func(c *config) { c.tracerProvider = tp }
}

// WithMeterProvider sets a custom MeterProvider. Defaults to the global provider.
func WithMeterProvider(mp metric.MeterProvider) Option {
	return func(c *config) { c.meterProvider = mp }
}

// NewEventHandler creates an authlog.EventHandler that emits OTel spans and metrics.
func NewEventHandler(opts ...Option) *EventHandler {
	cfg := &config{
		tracerProvider: otel.GetTracerProvider(),
		meterProvider:  otel.GetMeterProvider(),
	}
	for _, o := range opts {
		o(cfg)
	}

	tracer := cfg.tracerProvider.Tracer(instrumentationName)
	meter := cfg.meterProvider.Meter(instrumentationName)

	authTotal, _ := meter.Int64Counter("m2mauth.auth.total",
		metric.WithDescription("Total authentication attempts"),
		metric.WithUnit("{attempt}"),
	)
	authDuration, _ := meter.Float64Histogram("m2mauth.auth.duration",
		metric.WithDescription("Authentication validation duration"),
		metric.WithUnit("ms"),
	)
	tokenTotal, _ := meter.Int64Counter("m2mauth.token.total",
		metric.WithDescription("Total token acquisition attempts"),
		metric.WithUnit("{attempt}"),
	)
	tokenDuration, _ := meter.Float64Histogram("m2mauth.token.duration",
		metric.WithDescription("Token acquisition duration"),
		metric.WithUnit("ms"),
	)
	certEvents, _ := meter.Int64Counter("m2mauth.cert.events",
		metric.WithDescription("Certificate lifecycle events"),
		metric.WithUnit("{event}"),
	)

	return &EventHandler{
		tracer:        tracer,
		meter:         meter,
		authTotal:     authTotal,
		authDuration:  authDuration,
		tokenTotal:    tokenTotal,
		tokenDuration: tokenDuration,
		certEvents:    certEvents,
	}
}

// HandleEvent processes an auth event by emitting OTel spans and recording metrics.
func (h *EventHandler) HandleEvent(ctx context.Context, event authlog.Event) {
	attrs := []attribute.KeyValue{
		attribute.String("m2mauth.event_type", string(event.Type)),
		attribute.String("m2mauth.service", event.Service),
	}
	for k, v := range event.Details {
		attrs = append(attrs, attribute.String("m2mauth."+k, v))
	}

	switch event.Type {
	case authlog.EventAuthSuccess, authlog.EventAuthFailure:
		h.handleAuthEvent(ctx, event, attrs)
	case authlog.EventTokenAcquired, authlog.EventTokenRefreshed, authlog.EventTokenFetchErr:
		h.handleTokenEvent(ctx, event, attrs)
	case authlog.EventTokenRevoked, authlog.EventTokenExpired:
		h.handleTokenLifecycle(ctx, event, attrs)
	case authlog.EventCertRotated, authlog.EventCertExpiring, authlog.EventCertLoadErr:
		h.handleCertEvent(ctx, event, attrs)
	case authlog.EventJWKSRefreshed, authlog.EventJWKSFetchErr:
		h.handleJWKSEvent(ctx, event, attrs)
	default:
		h.handleGenericEvent(ctx, event, attrs)
	}
}

func (h *EventHandler) handleAuthEvent(ctx context.Context, event authlog.Event, attrs []attribute.KeyValue) {
	spanName := "m2mauth.auth.validate"
	status := "success"
	if event.Type == authlog.EventAuthFailure {
		status = "failure"
	}
	attrs = append(attrs, attribute.String("m2mauth.auth.status", status))

	_, span := h.tracer.Start(ctx, spanName,
		trace.WithSpanKind(trace.SpanKindServer),
		trace.WithAttributes(attrs...),
	)
	if event.Error != nil {
		span.SetStatus(codes.Error, event.Error.Error())
		span.RecordError(event.Error)
	}
	span.End()

	h.authTotal.Add(ctx, 1,
		metric.WithAttributes(
			attribute.String("service", event.Service),
			attribute.String("status", status),
		),
	)
	if event.Duration > 0 {
		h.authDuration.Record(ctx, float64(event.Duration.Milliseconds()),
			metric.WithAttributes(
				attribute.String("service", event.Service),
				attribute.String("status", status),
			),
		)
	}
}

func (h *EventHandler) handleTokenEvent(ctx context.Context, event authlog.Event, attrs []attribute.KeyValue) {
	spanName := "m2mauth.token.fetch"
	status := "success"
	if event.Type == authlog.EventTokenFetchErr {
		status = "error"
	}
	attrs = append(attrs, attribute.String("m2mauth.token.status", status))

	_, span := h.tracer.Start(ctx, spanName,
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(attrs...),
	)
	if event.Error != nil {
		span.SetStatus(codes.Error, event.Error.Error())
		span.RecordError(event.Error)
	}
	span.End()

	h.tokenTotal.Add(ctx, 1,
		metric.WithAttributes(
			attribute.String("service", event.Service),
			attribute.String("status", status),
		),
	)
	if event.Duration > 0 {
		h.tokenDuration.Record(ctx, float64(event.Duration.Milliseconds()),
			metric.WithAttributes(
				attribute.String("service", event.Service),
				attribute.String("status", status),
			),
		)
	}
}

func (h *EventHandler) handleTokenLifecycle(ctx context.Context, event authlog.Event, attrs []attribute.KeyValue) {
	_, span := h.tracer.Start(ctx, "m2mauth.token."+string(event.Type),
		trace.WithAttributes(attrs...),
	)
	span.End()

	h.tokenTotal.Add(ctx, 1,
		metric.WithAttributes(
			attribute.String("service", event.Service),
			attribute.String("status", string(event.Type)),
		),
	)
}

func (h *EventHandler) handleCertEvent(ctx context.Context, event authlog.Event, attrs []attribute.KeyValue) {
	spanName := "m2mauth.cert." + string(event.Type)
	_, span := h.tracer.Start(ctx, spanName,
		trace.WithAttributes(attrs...),
	)
	if event.Error != nil {
		span.SetStatus(codes.Error, event.Error.Error())
		span.RecordError(event.Error)
	}
	span.End()

	h.certEvents.Add(ctx, 1,
		metric.WithAttributes(
			attribute.String("service", event.Service),
			attribute.String("event_type", string(event.Type)),
		),
	)
}

func (h *EventHandler) handleJWKSEvent(ctx context.Context, event authlog.Event, attrs []attribute.KeyValue) {
	spanName := "m2mauth.jwks.refresh"
	_, span := h.tracer.Start(ctx, spanName,
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(attrs...),
	)
	if event.Error != nil {
		span.SetStatus(codes.Error, event.Error.Error())
		span.RecordError(event.Error)
	}
	span.End()
}

func (h *EventHandler) handleGenericEvent(ctx context.Context, event authlog.Event, attrs []attribute.KeyValue) {
	_, span := h.tracer.Start(ctx, "m2mauth."+string(event.Type),
		trace.WithAttributes(attrs...),
	)
	if event.Error != nil {
		span.SetStatus(codes.Error, event.Error.Error())
		span.RecordError(event.Error)
	}
	span.End()
}
