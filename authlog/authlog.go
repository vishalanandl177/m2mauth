// Package authlog provides structured logging, metrics, and audit events
// for authentication operations throughout the m2mauth library.
package authlog

import (
	"context"
	"log/slog"
	"time"
)

// EventType categorizes authentication events.
type EventType string

const (
	EventTokenAcquired  EventType = "token_acquired"
	EventTokenRefreshed EventType = "token_refreshed"
	EventTokenExpired   EventType = "token_expired"
	EventTokenRevoked   EventType = "token_revoked"
	EventTokenFetchErr  EventType = "token_fetch_error"
	EventAuthSuccess    EventType = "auth_success"
	EventAuthFailure    EventType = "auth_failure"
	EventCertRotated    EventType = "cert_rotated"
	EventCertExpiring   EventType = "cert_expiring"
	EventCertLoadErr    EventType = "cert_load_error"
	EventJWKSRefreshed  EventType = "jwks_refreshed"
	EventJWKSFetchErr   EventType = "jwks_fetch_error"
	EventKeyRotated     EventType = "key_rotated"
)

// Event represents a single authentication event for logging/audit.
type Event struct {
	// Type categorizes the event.
	Type EventType

	// Timestamp is when the event occurred.
	Timestamp time.Time

	// Service identifies the service or component that generated the event.
	Service string

	// Details holds arbitrary key-value metadata.
	Details map[string]string

	// Duration is the time taken for the operation (if applicable).
	Duration time.Duration

	// Error is the underlying error (if the event represents a failure).
	Error error
}

// EventHandler receives and processes authentication events.
type EventHandler interface {
	HandleEvent(ctx context.Context, event Event)
}

// EventHandlerFunc is an adapter to allow ordinary functions as EventHandlers.
type EventHandlerFunc func(ctx context.Context, event Event)

func (f EventHandlerFunc) HandleEvent(ctx context.Context, event Event) { f(ctx, event) }

// MultiHandler fans out events to multiple handlers.
type MultiHandler struct {
	handlers []EventHandler
}

// NewMultiHandler creates a handler that dispatches to all given handlers.
func NewMultiHandler(handlers ...EventHandler) *MultiHandler {
	return &MultiHandler{handlers: handlers}
}

func (m *MultiHandler) HandleEvent(ctx context.Context, event Event) {
	for _, h := range m.handlers {
		h.HandleEvent(ctx, event)
	}
}

// SlogHandler logs events via slog.
type SlogHandler struct {
	logger *slog.Logger
}

// NewSlogHandler creates an EventHandler that logs to the given slog.Logger.
func NewSlogHandler(logger *slog.Logger) *SlogHandler {
	return &SlogHandler{logger: logger}
}

func (h *SlogHandler) HandleEvent(_ context.Context, event Event) {
	attrs := []slog.Attr{
		slog.String("event_type", string(event.Type)),
		slog.String("service", event.Service),
		slog.Time("timestamp", event.Timestamp),
	}
	if event.Duration > 0 {
		attrs = append(attrs, slog.Duration("duration", event.Duration))
	}
	for k, v := range event.Details {
		attrs = append(attrs, slog.String(k, v))
	}

	args := make([]any, len(attrs))
	for i, a := range attrs {
		args[i] = a
	}

	if event.Error != nil {
		args = append(args, slog.String("error", event.Error.Error()))
		h.logger.Error("auth event", args...)
	} else {
		h.logger.Info("auth event", args...)
	}
}

// NopHandler discards all events. Useful as a default.
func NopHandler() EventHandler {
	return EventHandlerFunc(func(context.Context, Event) {})
}

// MetricsCollector provides counters and histograms for auth operations.
// Implement this interface to integrate with Prometheus, OpenTelemetry, etc.
type MetricsCollector interface {
	TokenAcquired(service string, duration time.Duration)
	TokenRefreshFailed(service string, err error)
	AuthValidated(service string, duration time.Duration)
	AuthRejected(service string, reason string)
}

// NopMetrics returns a MetricsCollector that does nothing.
func NopMetrics() MetricsCollector { return nopMetrics{} }

type nopMetrics struct{}

func (nopMetrics) TokenAcquired(string, time.Duration) {}
func (nopMetrics) TokenRefreshFailed(string, error)    {}
func (nopMetrics) AuthValidated(string, time.Duration) {}
func (nopMetrics) AuthRejected(string, string)         {}

// Emit is a convenience function for sending an event to a handler.
func Emit(ctx context.Context, h EventHandler, evType EventType, service string, details map[string]string, dur time.Duration, err error) {
	if h == nil {
		return
	}
	h.HandleEvent(ctx, Event{
		Type:      evType,
		Timestamp: time.Now(),
		Service:   service,
		Details:   details,
		Duration:  dur,
		Error:     err,
	})
}
