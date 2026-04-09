// Package retry provides configurable exponential backoff with jitter
// for retrying operations that may transiently fail.
package retry

import (
	"context"
	"math"
	"math/rand/v2"
	"time"
)

// Policy configures retry behavior.
type Policy struct {
	// MaxRetries is the maximum number of retry attempts (0 means no retries).
	MaxRetries int

	// BaseDelay is the initial delay before the first retry.
	BaseDelay time.Duration

	// MaxDelay caps the delay between retries.
	MaxDelay time.Duration

	// Jitter adds randomness to delays (0.0-1.0). 0.2 means +/- 20%.
	Jitter float64

	// ShouldRetry determines whether an error is retryable.
	// If nil, all errors are retried.
	ShouldRetry func(error) bool
}

// DefaultPolicy returns a sensible default retry policy.
func DefaultPolicy() Policy {
	return Policy{
		MaxRetries: 3,
		BaseDelay:  100 * time.Millisecond,
		MaxDelay:   10 * time.Second,
		Jitter:     0.2,
	}
}

// Option configures a Policy.
type Option func(*Policy)

// WithMaxRetries sets the maximum retry count.
func WithMaxRetries(n int) Option {
	return func(p *Policy) { p.MaxRetries = n }
}

// WithBaseDelay sets the initial backoff delay.
func WithBaseDelay(d time.Duration) Option {
	return func(p *Policy) { p.BaseDelay = d }
}

// WithMaxDelay caps the maximum backoff delay.
func WithMaxDelay(d time.Duration) Option {
	return func(p *Policy) { p.MaxDelay = d }
}

// WithJitter sets the jitter factor (0.0 to 1.0).
func WithJitter(j float64) Option {
	return func(p *Policy) { p.Jitter = j }
}

// WithShouldRetry sets a custom function to determine retryable errors.
func WithShouldRetry(fn func(error) bool) Option {
	return func(p *Policy) { p.ShouldRetry = fn }
}

// NewPolicy creates a Policy from options, starting from DefaultPolicy.
func NewPolicy(opts ...Option) Policy {
	p := DefaultPolicy()
	for _, o := range opts {
		o(&p)
	}
	return p
}

// Do executes fn, retrying on error according to the policy.
// It respects context cancellation between attempts.
func Do(ctx context.Context, p Policy, fn func(ctx context.Context) error) error {
	var lastErr error
	for attempt := 0; attempt <= p.MaxRetries; attempt++ {
		lastErr = fn(ctx)
		if lastErr == nil {
			return nil
		}

		if p.ShouldRetry != nil && !p.ShouldRetry(lastErr) {
			return lastErr
		}

		if attempt == p.MaxRetries {
			break
		}

		delay := p.backoff(attempt)
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return lastErr
}

func (p Policy) backoff(attempt int) time.Duration {
	delay := float64(p.BaseDelay) * math.Pow(2, float64(attempt))
	if delay > float64(p.MaxDelay) {
		delay = float64(p.MaxDelay)
	}

	if p.Jitter > 0 {
		jitter := delay * p.Jitter
		delay = delay - jitter + (rand.Float64() * 2 * jitter)
	}

	return time.Duration(delay)
}
