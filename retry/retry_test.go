package retry

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestDo_Success(t *testing.T) {
	calls := 0
	err := Do(context.Background(), DefaultPolicy(), func(ctx context.Context) error {
		calls++
		return nil
	})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected 1 call, got %d", calls)
	}
}

func TestDo_RetryThenSuccess(t *testing.T) {
	p := NewPolicy(WithMaxRetries(3), WithBaseDelay(time.Millisecond), WithMaxDelay(10*time.Millisecond))
	calls := 0
	err := Do(context.Background(), p, func(ctx context.Context) error {
		calls++
		if calls < 3 {
			return errors.New("transient")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if calls != 3 {
		t.Fatalf("expected 3 calls, got %d", calls)
	}
}

func TestDo_MaxRetriesExhausted(t *testing.T) {
	p := NewPolicy(WithMaxRetries(2), WithBaseDelay(time.Millisecond))
	calls := 0
	sentinel := errors.New("permanent")
	err := Do(context.Background(), p, func(ctx context.Context) error {
		calls++
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected sentinel error, got %v", err)
	}
	if calls != 3 { // 1 initial + 2 retries
		t.Fatalf("expected 3 calls, got %d", calls)
	}
}

func TestDo_ShouldRetryFalse(t *testing.T) {
	p := NewPolicy(
		WithMaxRetries(5),
		WithBaseDelay(time.Millisecond),
		WithShouldRetry(func(err error) bool { return false }),
	)
	calls := 0
	err := Do(context.Background(), p, func(ctx context.Context) error {
		calls++
		return errors.New("non-retryable")
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if calls != 1 {
		t.Fatalf("expected 1 call (no retries), got %d", calls)
	}
}

func TestDo_ContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	p := NewPolicy(WithMaxRetries(10), WithBaseDelay(time.Second))
	calls := 0

	go func() {
		time.Sleep(5 * time.Millisecond)
		cancel()
	}()

	err := Do(ctx, p, func(ctx context.Context) error {
		calls++
		return errors.New("fail")
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestBackoff(t *testing.T) {
	p := Policy{BaseDelay: 100 * time.Millisecond, MaxDelay: 5 * time.Second, Jitter: 0}
	d0 := p.backoff(0)
	d1 := p.backoff(1)
	d2 := p.backoff(2)
	if d0 != 100*time.Millisecond {
		t.Errorf("attempt 0: got %v, want 100ms", d0)
	}
	if d1 != 200*time.Millisecond {
		t.Errorf("attempt 1: got %v, want 200ms", d1)
	}
	if d2 != 400*time.Millisecond {
		t.Errorf("attempt 2: got %v, want 400ms", d2)
	}

	// Test max delay cap
	d10 := p.backoff(20)
	if d10 != 5*time.Second {
		t.Errorf("attempt 20: got %v, want 5s (capped)", d10)
	}
}

func TestBackoff_WithJitter(t *testing.T) {
	p := NewPolicy(WithBaseDelay(100*time.Millisecond), WithMaxDelay(10*time.Second), WithJitter(0.5))
	// With 50% jitter, delay should vary but stay in range [50ms, 150ms] for attempt 0
	min := 50 * time.Millisecond
	max := 150 * time.Millisecond
	for i := 0; i < 100; i++ {
		d := p.backoff(0)
		if d < min || d > max {
			t.Errorf("jittered delay %v outside expected range [%v, %v]", d, min, max)
		}
	}
}

func TestPolicy_Validate(t *testing.T) {
	tests := []struct {
		name    string
		policy  Policy
		wantErr bool
	}{
		{"valid default", DefaultPolicy(), false},
		{"negative retries", Policy{MaxRetries: -1, BaseDelay: time.Second, MaxDelay: time.Second}, true},
		{"negative base delay", Policy{MaxRetries: 1, BaseDelay: -time.Second, MaxDelay: time.Second}, true},
		{"base > max", Policy{MaxRetries: 1, BaseDelay: 10 * time.Second, MaxDelay: time.Second}, true},
		{"jitter too high", Policy{MaxRetries: 1, BaseDelay: time.Second, MaxDelay: 10 * time.Second, Jitter: 1.5}, true},
		{"negative jitter", Policy{MaxRetries: 1, BaseDelay: time.Second, MaxDelay: 10 * time.Second, Jitter: -0.1}, true},
		{"zero max delay ok", Policy{MaxRetries: 1, BaseDelay: time.Second, MaxDelay: 0}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.policy.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
