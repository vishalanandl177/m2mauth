package clock

import (
	"testing"
	"time"
)

func TestRealClock(t *testing.T) {
	c := Real()
	before := time.Now()
	got := c.Now()
	after := time.Now()

	if got.Before(before) || got.After(after) {
		t.Errorf("Real clock time %v not in expected range [%v, %v]", got, before, after)
	}
}

func TestMockClock(t *testing.T) {
	base := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	m := NewMock(base)

	if got := m.Now(); !got.Equal(base) {
		t.Errorf("expected %v, got %v", base, got)
	}

	m.Advance(5 * time.Minute)
	expected := base.Add(5 * time.Minute)
	if got := m.Now(); !got.Equal(expected) {
		t.Errorf("expected %v after Advance, got %v", expected, got)
	}

	newTime := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	m.Set(newTime)
	if got := m.Now(); !got.Equal(newTime) {
		t.Errorf("expected %v after Set, got %v", newTime, got)
	}
}
