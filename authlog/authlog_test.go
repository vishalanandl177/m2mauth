package authlog

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func TestEmit_NilHandler(t *testing.T) {
	// Should not panic with nil handler.
	Emit(context.Background(), nil, EventTokenAcquired, "test-svc", nil, 0, nil)
}

func TestEmit_EventFields(t *testing.T) {
	var captured Event
	h := EventHandlerFunc(func(_ context.Context, e Event) {
		captured = e
	})

	testErr := errors.New("fetch failed")
	details := map[string]string{"token_url": "https://auth.example.com/token"}
	Emit(context.Background(), h, EventTokenFetchErr, "my-service", details, 150*time.Millisecond, testErr)

	if captured.Type != EventTokenFetchErr {
		t.Errorf("expected type %s, got %s", EventTokenFetchErr, captured.Type)
	}
	if captured.Service != "my-service" {
		t.Errorf("expected service my-service, got %s", captured.Service)
	}
	if captured.Details["token_url"] != "https://auth.example.com/token" {
		t.Errorf("expected token_url detail, got %v", captured.Details)
	}
	if captured.Duration != 150*time.Millisecond {
		t.Errorf("expected 150ms duration, got %v", captured.Duration)
	}
	if captured.Error != testErr {
		t.Errorf("expected error %v, got %v", testErr, captured.Error)
	}
	if captured.Timestamp.IsZero() {
		t.Error("expected non-zero timestamp")
	}
}

func TestNopHandler(t *testing.T) {
	h := NopHandler()
	// Should not panic.
	h.HandleEvent(context.Background(), Event{Type: EventAuthSuccess})
}

func TestMultiHandler(t *testing.T) {
	var count int
	h1 := EventHandlerFunc(func(_ context.Context, _ Event) { count++ })
	h2 := EventHandlerFunc(func(_ context.Context, _ Event) { count++ })

	multi := NewMultiHandler(h1, h2)
	multi.HandleEvent(context.Background(), Event{Type: EventAuthSuccess, Service: "test"})

	if count != 2 {
		t.Errorf("expected 2 handler calls, got %d", count)
	}
}

func TestSlogHandler_InfoEvent(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	h := NewSlogHandler(logger)

	h.HandleEvent(context.Background(), Event{
		Type:      EventTokenAcquired,
		Timestamp: time.Now(),
		Service:   "my-svc",
		Duration:  200 * time.Millisecond,
		Details:   map[string]string{"expires_in": "3600s"},
	})

	output := buf.String()
	if !strings.Contains(output, "auth event") {
		t.Errorf("expected 'auth event' in log output, got: %s", output)
	}
	if !strings.Contains(output, "token_acquired") {
		t.Errorf("expected 'token_acquired' in log output, got: %s", output)
	}
	if !strings.Contains(output, "my-svc") {
		t.Errorf("expected 'my-svc' in log output, got: %s", output)
	}
}

func TestSlogHandler_ErrorEvent(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	h := NewSlogHandler(logger)

	h.HandleEvent(context.Background(), Event{
		Type:      EventTokenFetchErr,
		Timestamp: time.Now(),
		Service:   "my-svc",
		Error:     errors.New("connection refused"),
	})

	output := buf.String()
	if !strings.Contains(output, "ERROR") {
		t.Errorf("expected ERROR level in log output, got: %s", output)
	}
	if !strings.Contains(output, "connection refused") {
		t.Errorf("expected error message in log output, got: %s", output)
	}
}

func TestNopMetrics(t *testing.T) {
	m := NopMetrics()
	// Should not panic.
	m.TokenAcquired("svc", time.Second)
	m.TokenRefreshFailed("svc", errors.New("fail"))
	m.AuthValidated("svc", time.Second)
	m.AuthRejected("svc", "expired")
}
