// Package clock provides a mockable time source for testing.
package clock

import "time"

// Clock provides the current time. Use Real() in production
// and Mock() in tests.
type Clock interface {
	Now() time.Time
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

// Real returns a Clock backed by the system clock.
func Real() Clock { return realClock{} }

// Mock returns a Clock that returns a fixed time, advanceable for testing.
type Mock struct {
	current time.Time
}

// NewMock creates a Mock clock set to the given time.
func NewMock(t time.Time) *Mock {
	return &Mock{current: t}
}

// Now returns the mock's current time.
func (m *Mock) Now() time.Time { return m.current }

// Advance moves the mock clock forward by d.
func (m *Mock) Advance(d time.Duration) { m.current = m.current.Add(d) }

// Set sets the mock clock to t.
func (m *Mock) Set(t time.Time) { m.current = t }
