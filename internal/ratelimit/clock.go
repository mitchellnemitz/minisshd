package ratelimit

import (
	"sync"
	"time"
)

// Clock abstracts time.Now for testability. Production code uses
// RealClock; tests inject FakeClock and drive it forward deterministically
// so the unit tests do not block on real wall-clock sleeps.
//
// All time math in this package goes through this interface; nothing in
// the limiter calls time.Now() directly.
type Clock interface {
	Now() time.Time
}

// RealClock is a Clock backed by time.Now. The returned Time carries the
// monotonic component, so subsequent t.Sub() / time.Since() calls are
// immune to wall-clock NTP adjustments — see spec §5 Memory bound.
type RealClock struct{}

// Now returns time.Now(). RealClock has no fields so an instance can be
// passed by value with zero cost.
func (RealClock) Now() time.Time { return time.Now() }

// FakeClock is a deterministic Clock for tests. Construct it with
// NewFakeClock(start) and advance with Advance(d). Concurrent reads and
// advances are safe.
//
// FakeClock is also exported (capitalized) because the §13.3 integration
// suite reuses it; the ratelimit unit tests live alongside production
// code, so the type does not need a leading underscore.
type FakeClock struct {
	mu  sync.Mutex
	now time.Time
}

// NewFakeClock returns a FakeClock whose Now() initially reports the
// given time. Tests typically start at time.Unix(0, 0) or some recognized
// anchor.
func NewFakeClock(start time.Time) *FakeClock {
	return &FakeClock{now: start}
}

// Now returns the current fake time.
func (f *FakeClock) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

// Advance moves the fake clock forward by d. Negative values are
// rejected (the limiter relies on monotonic time).
func (f *FakeClock) Advance(d time.Duration) {
	if d < 0 {
		panic("FakeClock.Advance: negative duration")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = f.now.Add(d)
}
