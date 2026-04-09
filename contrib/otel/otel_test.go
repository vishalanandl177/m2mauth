package otel

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/vishalanandl177/m2mauth/authlog"
)

func TestNewEventHandler_Defaults(t *testing.T) {
	h := NewEventHandler()
	if h.tracer == nil {
		t.Fatal("expected non-nil tracer")
	}
	if h.meter == nil {
		t.Fatal("expected non-nil meter")
	}
}

func TestHandleEvent_AuthSuccess(t *testing.T) {
	h := NewEventHandler()
	h.HandleEvent(context.Background(), authlog.Event{
		Type:      authlog.EventAuthSuccess,
		Timestamp: time.Now(),
		Service:   "test-svc",
		Details:   map[string]string{"subject": "svc-orders"},
		Duration:  50 * time.Millisecond,
	})
}

func TestHandleEvent_AuthFailure(t *testing.T) {
	h := NewEventHandler()
	h.HandleEvent(context.Background(), authlog.Event{
		Type:      authlog.EventAuthFailure,
		Timestamp: time.Now(),
		Service:   "test-svc",
		Details:   map[string]string{"reason": "invalid_token"},
		Duration:  5 * time.Millisecond,
		Error:     errors.New("token expired"),
	})
}

func TestHandleEvent_TokenAcquired(t *testing.T) {
	h := NewEventHandler()
	h.HandleEvent(context.Background(), authlog.Event{
		Type:      authlog.EventTokenAcquired,
		Timestamp: time.Now(),
		Service:   "oauth-client",
		Duration:  200 * time.Millisecond,
	})
}

func TestHandleEvent_TokenFetchError(t *testing.T) {
	h := NewEventHandler()
	h.HandleEvent(context.Background(), authlog.Event{
		Type:      authlog.EventTokenFetchErr,
		Timestamp: time.Now(),
		Service:   "oauth-client",
		Duration:  1 * time.Second,
		Error:     errors.New("connection refused"),
	})
}

func TestHandleEvent_TokenRevoked(t *testing.T) {
	h := NewEventHandler()
	h.HandleEvent(context.Background(), authlog.Event{
		Type:      authlog.EventTokenRevoked,
		Timestamp: time.Now(),
		Service:   "test-svc",
	})
}

func TestHandleEvent_CertRotated(t *testing.T) {
	h := NewEventHandler()
	h.HandleEvent(context.Background(), authlog.Event{
		Type:      authlog.EventCertRotated,
		Timestamp: time.Now(),
		Service:   "mtls-client",
		Details:   map[string]string{"cert_file": "/etc/certs/client.crt"},
	})
}

func TestHandleEvent_CertLoadErr(t *testing.T) {
	h := NewEventHandler()
	h.HandleEvent(context.Background(), authlog.Event{
		Type:      authlog.EventCertLoadErr,
		Timestamp: time.Now(),
		Service:   "mtls-client",
		Error:     errors.New("file not found"),
	})
}

func TestHandleEvent_JWKSRefreshed(t *testing.T) {
	h := NewEventHandler()
	h.HandleEvent(context.Background(), authlog.Event{
		Type:      authlog.EventJWKSRefreshed,
		Timestamp: time.Now(),
		Service:   "jwt-validator",
	})
}

func TestHandleEvent_JWKSFetchErr(t *testing.T) {
	h := NewEventHandler()
	h.HandleEvent(context.Background(), authlog.Event{
		Type:      authlog.EventJWKSFetchErr,
		Timestamp: time.Now(),
		Service:   "jwt-validator",
		Error:     errors.New("network error"),
	})
}

func TestHandleEvent_GenericEvent(t *testing.T) {
	h := NewEventHandler()
	h.HandleEvent(context.Background(), authlog.Event{
		Type:      authlog.EventKeyRotated,
		Timestamp: time.Now(),
		Service:   "test-svc",
	})
}

func TestHandleEvent_AllEventTypes(t *testing.T) {
	h := NewEventHandler()
	events := []authlog.EventType{
		authlog.EventTokenAcquired,
		authlog.EventTokenRefreshed,
		authlog.EventTokenExpired,
		authlog.EventTokenRevoked,
		authlog.EventTokenFetchErr,
		authlog.EventAuthSuccess,
		authlog.EventAuthFailure,
		authlog.EventCertRotated,
		authlog.EventCertExpiring,
		authlog.EventCertLoadErr,
		authlog.EventJWKSRefreshed,
		authlog.EventJWKSFetchErr,
		authlog.EventKeyRotated,
	}

	for _, et := range events {
		h.HandleEvent(context.Background(), authlog.Event{
			Type:      et,
			Timestamp: time.Now(),
			Service:   "test-svc",
		})
	}
}
