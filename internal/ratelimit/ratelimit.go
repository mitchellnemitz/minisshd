// Package ratelimit implements the per-IP exponential backoff described
// in spec §5. The limiter is keyed by client IP (IPv4-mapped IPv6
// normalized to bare IPv4), tracks fail_count + last_fail per IP, and
// serializes the compute-delay → sleep → callback → record sequence with
// a per-IP mutex so concurrent attempts cannot race past the first-attempt
// delay.
package ratelimit

import (
	"net"
	"sync"
	"time"
)

// MaxDelay is the cap on the exponential backoff, per spec §5: the
// sequence over rising fail_count is 1s, 2s, 4s, 8s, 16s, 32s, 60s, 60s, …
const MaxDelay = 60 * time.Second

// IdleExpiry is the lazy expiration window: an entry whose last_fail is
// older than this is treated as if it does not exist, per spec §5 Reset.
const IdleExpiry = 10 * time.Minute

// entry holds the per-IP state. Each entry also embeds its own mutex so
// the compute → sleep → callback → record sequence can be serialized
// without holding the outer map lock. See spec §5 "the per-IP locks are
// stored in the map values".
type entry struct {
	mu        sync.Mutex
	failCount int
	lastFail  time.Time
}

// Limiter is the per-IP backoff state machine. The zero value is not
// usable; construct one with New.
type Limiter struct {
	clock Clock

	// mu protects the entries map itself: reads under RLock, structural
	// changes (insert, delete) under Lock. The per-entry mutex serializes
	// the Acquire → release lifecycle for a single IP.
	mu      sync.RWMutex
	entries map[string]*entry
}

// New constructs a Limiter that uses the given Clock. Pass RealClock{} in
// production; tests inject a FakeClock.
func New(clock Clock) *Limiter {
	return &Limiter{
		clock:   clock,
		entries: make(map[string]*entry),
	}
}

// normalize implements the spec §5 normalization rule: IPv4-mapped IPv6
// addresses collapse to their bare IPv4 form so an attacker on a dual-
// stack listener cannot double their attempt budget by alternating
// between 127.0.0.1 and ::ffff:127.0.0.1. Pure IPv6 (e.g. 2001:db8::1,
// ::1) is preserved as-is.
func normalize(ip net.IP) net.IP {
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	return ip
}

// Acquire begins the per-IP-locked auth sequence for the given remote IP.
// The returned delay is the duration the caller MUST sleep before
// invoking the password callback (the limiter itself does not sleep —
// keeping it deterministically testable). The caller then invokes the
// callback and calls release(true) on success or release(false) on
// failure.
//
// The per-IP mutex is held from this call's return through the matching
// release call. This guarantees the compute-delay → sleep → callback →
// record sequence runs as a critical section per IP, per spec §5: "the
// 'compute delay → sleep → invoke password callback → record result'
// sequence must hold a per-IP lock for the entire duration; otherwise
// two simultaneous attempts from the same IP can both observe
// fail_count=0 and bypass the first-attempt delay."
//
// Acquire is also where the 10-minute lazy expiry runs: an entry whose
// last_fail is older than IdleExpiry is dropped before locking, so the
// next call sees a fresh counter and zero delay.
func (l *Limiter) Acquire(ip net.IP) (delay time.Duration, release func(success bool)) {
	ip = normalize(ip)
	key := ip.String()

	// Step 1: load-or-create the entry, then lock it before reading any
	// fields. Reading lastFail or failCount without the entry mutex
	// would race with a concurrent release(false). We therefore acquire
	// the per-IP mutex first, then check expiry; if the entry is stale
	// we drop it from the map (under the map write lock) and start
	// fresh.
	e := l.loadOrCreate(key)
	e.mu.Lock()

	now := l.clock.Now()
	if e.failCount > 0 && now.Sub(e.lastFail) > IdleExpiry {
		// Stale entry. Remove from the map and create a fresh one for
		// the caller. Order: release the stale entry mutex, take the
		// map write lock to swap, then lock the new entry mutex.
		e.mu.Unlock()
		l.mu.Lock()
		if cur, present := l.entries[key]; present && cur == e {
			delete(l.entries, key)
		}
		l.mu.Unlock()
		e = l.loadOrCreate(key)
		e.mu.Lock()
	}

	// Step 2: compute the delay from the current fail_count under the
	// per-IP lock — this is the snapshot that the caller sleeps for and
	// that is preserved across the callback.
	delay = computeDelay(e.failCount)

	release = func(success bool) {
		if success {
			// Spec §5 Reset: successful auth deletes the entry. We hold
			// the entry mutex, which keeps any other Acquire that already
			// observed this entry blocked behind us; but to remove from
			// the map we need the outer write lock. Order matters: take
			// the outer lock first, delete, then drop the entry mutex.
			// The released entry mutex is harmless even if another
			// Acquire was about to reuse it, because the structural
			// remove ensures future Acquires get a fresh entry.
			l.mu.Lock()
			// Only delete if the map still points at this entry; another
			// Acquire could have raced through expiry and replaced it.
			if cur, present := l.entries[key]; present && cur == e {
				delete(l.entries, key)
			}
			l.mu.Unlock()
			e.mu.Unlock()
			return
		}
		// Failure path: increment fail_count and refresh last_fail.
		e.failCount++
		e.lastFail = l.clock.Now()
		e.mu.Unlock()
	}

	return delay, release
}

// loadOrCreate returns the entry for key, creating it under the map
// write lock if it does not exist. The returned entry's per-IP mutex is
// NOT held — the caller is expected to lock it next.
func (l *Limiter) loadOrCreate(key string) *entry {
	l.mu.RLock()
	if e, ok := l.entries[key]; ok {
		l.mu.RUnlock()
		return e
	}
	l.mu.RUnlock()

	l.mu.Lock()
	if e, ok := l.entries[key]; ok {
		l.mu.Unlock()
		return e
	}
	e := &entry{}
	l.entries[key] = e
	l.mu.Unlock()
	return e
}

// computeDelay implements the formula from spec §5:
//
//	delay = 0                                if fail_count == 0
//	delay = min(60s, 2^(fail_count - 1) * 1s) otherwise
//
// Verified sequence for fail_count = 1..8 → 1s, 2s, 4s, 8s, 16s, 32s, 60s, 60s.
func computeDelay(failCount int) time.Duration {
	if failCount <= 0 {
		return 0
	}
	// Cap the shift exponent to avoid undefined behavior on absurdly
	// large counters. 2^62 seconds far exceeds MaxDelay anyway; the cap
	// kicks in well before.
	exp := failCount - 1
	if exp > 62 {
		return MaxDelay
	}
	d := time.Duration(int64(1)<<exp) * time.Second
	if d > MaxDelay || d < 0 { // d<0 catches overflow on signed shift
		return MaxDelay
	}
	return d
}

// Snapshot returns a defensive copy of the current per-IP fail counts,
// keyed by the normalized IP string. The §13.3 IPv4-mapped IPv6
// integration test asserts on this surface; the same surface is useful
// for an eventual admin endpoint and so is not test-only.
//
// The returned map is safe for the caller to mutate without affecting
// internal state.
func (l *Limiter) Snapshot() map[string]int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	out := make(map[string]int, len(l.entries))
	for k, e := range l.entries {
		// Grab fail_count under the entry mutex to avoid a data race
		// with an in-flight release(false).
		e.mu.Lock()
		out[k] = e.failCount
		e.mu.Unlock()
	}
	return out
}
