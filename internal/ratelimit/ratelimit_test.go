package ratelimit

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func mustParseIP(t *testing.T, s string) net.IP {
	t.Helper()
	ip := net.ParseIP(s)
	if ip == nil {
		t.Fatalf("net.ParseIP(%q) failed", s)
	}
	return ip
}

// TestComputeDelay_Sequence verifies the exact backoff table from spec
// §5: fail_count = 0,1,2,3,4,5,6,7,8 → 0,1,2,4,8,16,32,60,60 seconds.
func TestComputeDelay_Sequence(t *testing.T) {
	want := map[int]time.Duration{
		0: 0,
		1: 1 * time.Second,
		2: 2 * time.Second,
		3: 4 * time.Second,
		4: 8 * time.Second,
		5: 16 * time.Second,
		6: 32 * time.Second,
		7: 60 * time.Second,
		8: 60 * time.Second,
		9: 60 * time.Second,
		// Spec §13.2: delay(20) == 60s.
		20: 60 * time.Second,
		// Pathological large values still clamp to MaxDelay.
		200: 60 * time.Second,
	}
	for fc, w := range want {
		if got := computeDelay(fc); got != w {
			t.Errorf("computeDelay(%d) = %v, want %v", fc, got, w)
		}
	}
}

// TestAcquire_DelaySequenceUnderFakeClock walks Acquire+release(false)
// repeatedly and asserts the delay returned each round matches the table
// from spec §5. The fake clock means this test runs in microseconds, not
// minutes.
func TestAcquire_DelaySequenceUnderFakeClock(t *testing.T) {
	clk := NewFakeClock(time.Unix(0, 0))
	l := New(clk)
	ip := mustParseIP(t, "192.0.2.1")

	want := []time.Duration{
		0,
		1 * time.Second,
		2 * time.Second,
		4 * time.Second,
		8 * time.Second,
		16 * time.Second,
		32 * time.Second,
		60 * time.Second,
		60 * time.Second,
	}
	for i, w := range want {
		got, rel := l.Acquire(ip)
		if got != w {
			t.Errorf("round %d: delay = %v, want %v", i, got, w)
		}
		rel(false)
		// Nudge the clock a millisecond so each lastFail is distinct
		// — not required by the limiter but mirrors reality.
		clk.Advance(time.Millisecond)
	}
}

// TestRelease_FailureIncrementsCounterAndUpdatesLastFail asserts the
// failure path bumps fail_count and refreshes last_fail. Verified via the
// public Snapshot() surface.
func TestRelease_FailureIncrementsCounterAndUpdatesLastFail(t *testing.T) {
	clk := NewFakeClock(time.Unix(0, 0))
	l := New(clk)
	ip := mustParseIP(t, "192.0.2.2")

	_, rel := l.Acquire(ip)
	rel(false)
	if snap := l.Snapshot(); snap["192.0.2.2"] != 1 {
		t.Fatalf("after first failure, fail_count = %d, want 1", snap["192.0.2.2"])
	}

	clk.Advance(5 * time.Second)
	_, rel = l.Acquire(ip)
	rel(false)
	if snap := l.Snapshot(); snap["192.0.2.2"] != 2 {
		t.Fatalf("after second failure, fail_count = %d, want 2", snap["192.0.2.2"])
	}

	// Inspect lastFail through internal access since Snapshot only exposes
	// counts. We're in the same package so this is fine.
	l.mu.RLock()
	e := l.entries["192.0.2.2"]
	l.mu.RUnlock()
	e.mu.Lock()
	got := e.lastFail
	e.mu.Unlock()
	wantLast := time.Unix(0, 0).Add(5 * time.Second)
	if !got.Equal(wantLast) {
		t.Errorf("lastFail = %v, want %v", got, wantLast)
	}
}

// TestAcquire_LazyExpiryClearsAfterTenMinutes proves the 10-minute idle
// reset: after a failure, advance the fake clock past 10 minutes, then
// Acquire again — the delay must be zero and the previous counter gone.
func TestAcquire_LazyExpiryClearsAfterTenMinutes(t *testing.T) {
	clk := NewFakeClock(time.Unix(0, 0))
	l := New(clk)
	ip := mustParseIP(t, "192.0.2.3")

	// Record a couple of failures so the entry definitely exists.
	for i := 0; i < 3; i++ {
		_, rel := l.Acquire(ip)
		rel(false)
	}
	if snap := l.Snapshot(); snap["192.0.2.3"] != 3 {
		t.Fatalf("setup: fail_count = %d, want 3", snap["192.0.2.3"])
	}

	// Just shy of 10 minutes: still active.
	clk.Advance(IdleExpiry - 1*time.Second)
	delay, rel := l.Acquire(ip)
	if delay == 0 {
		t.Errorf("at 9m59s, expected non-zero delay but got 0 (entry expired prematurely)")
	}
	rel(false) // bumps to 4, refreshes lastFail to current fake clock

	// Now jump past 10 minutes from the new lastFail.
	clk.Advance(IdleExpiry + 1*time.Second)
	delay, rel = l.Acquire(ip)
	if delay != 0 {
		t.Errorf("after 10-min idle, delay = %v, want 0", delay)
	}
	rel(false)
	if snap := l.Snapshot(); snap["192.0.2.3"] != 1 {
		t.Errorf("after expiry then one failure, fail_count = %d, want 1 (fresh counter)", snap["192.0.2.3"])
	}
}

// TestRelease_SuccessRemovesEntry proves the spec §5 Reset rule: a
// successful auth deletes the per-IP entry so the next attempt sees zero
// delay.
func TestRelease_SuccessRemovesEntry(t *testing.T) {
	clk := NewFakeClock(time.Unix(0, 0))
	l := New(clk)
	ip := mustParseIP(t, "192.0.2.4")

	// Three failures.
	for i := 0; i < 3; i++ {
		_, rel := l.Acquire(ip)
		rel(false)
	}
	if snap := l.Snapshot(); snap["192.0.2.4"] != 3 {
		t.Fatalf("setup: fail_count = %d, want 3", snap["192.0.2.4"])
	}

	// One success.
	_, rel := l.Acquire(ip)
	rel(true)
	if snap := l.Snapshot(); len(snap) != 0 {
		t.Fatalf("after success, snapshot = %v, want empty map", snap)
	}

	// Subsequent Acquire sees zero delay.
	delay, rel := l.Acquire(ip)
	if delay != 0 {
		t.Errorf("after reset, delay = %v, want 0", delay)
	}
	rel(false)
}

// TestAcquire_IPv4MappedIPv6Normalization proves an attempt arriving with
// remote ::ffff:127.0.0.1 lands under the bare IPv4 key. This is the
// counterpart to the §13.3 dual-stack integration test.
func TestAcquire_IPv4MappedIPv6Normalization(t *testing.T) {
	clk := NewFakeClock(time.Unix(0, 0))
	l := New(clk)

	mapped := mustParseIP(t, "::ffff:127.0.0.1")
	_, rel := l.Acquire(mapped)
	rel(false)

	snap := l.Snapshot()
	if snap["127.0.0.1"] != 1 {
		t.Errorf("expected fail_count under \"127.0.0.1\" = 1, got snapshot %v", snap)
	}
	if _, present := snap["::ffff:127.0.0.1"]; present {
		t.Errorf("normalized form should not appear under the IPv6-mapped key, got %v", snap)
	}

	// Pure IPv6 stays as IPv6.
	pure := mustParseIP(t, "::1")
	_, rel = l.Acquire(pure)
	rel(false)
	snap = l.Snapshot()
	if snap["::1"] != 1 {
		t.Errorf("expected fail_count under \"::1\" = 1, got snapshot %v", snap)
	}
}

// TestSnapshot_DefensiveCopy proves mutating the returned map cannot
// corrupt internal state.
func TestSnapshot_DefensiveCopy(t *testing.T) {
	clk := NewFakeClock(time.Unix(0, 0))
	l := New(clk)
	ip := mustParseIP(t, "192.0.2.5")

	_, rel := l.Acquire(ip)
	rel(false)

	snap := l.Snapshot()
	snap["192.0.2.5"] = 999
	delete(snap, "192.0.2.5")
	snap["forged"] = 42

	again := l.Snapshot()
	if again["192.0.2.5"] != 1 {
		t.Errorf("internal state mutated through returned snapshot: %v", again)
	}
	if _, present := again["forged"]; present {
		t.Errorf("forged key leaked back into limiter state: %v", again)
	}
}

// TestAcquire_ConcurrentHammering runs 100 goroutines pounding a small
// set of IPs under -race. The goroutines each record a fixed number of
// failures; after all are done, the snapshot must reflect the exact
// total per IP. This validates both the locking discipline and the
// fail_count accounting. A concurrent reader hammers Snapshot to expose
// any race between Acquire/release and Snapshot.
func TestAcquire_ConcurrentHammering(t *testing.T) {
	clk := NewFakeClock(time.Unix(0, 0))
	l := New(clk)

	ips := []string{
		"192.0.2.10",
		"192.0.2.11",
		"192.0.2.12",
		"::1",
		"2001:db8::1",
	}
	const goroutinesPerIP = 20
	const failuresPerGoroutine = 5

	var writers sync.WaitGroup
	for _, ipStr := range ips {
		ip := mustParseIP(t, ipStr)
		for g := 0; g < goroutinesPerIP; g++ {
			writers.Add(1)
			go func(ip net.IP) {
				defer writers.Done()
				for i := 0; i < failuresPerGoroutine; i++ {
					_, rel := l.Acquire(ip)
					rel(false)
				}
			}(ip)
		}
	}

	// Concurrent Snapshot reader runs until the writers signal done.
	stop := make(chan struct{})
	readerDone := make(chan struct{})
	var snapshotReads int64
	go func() {
		defer close(readerDone)
		for {
			select {
			case <-stop:
				return
			default:
				_ = l.Snapshot()
				atomic.AddInt64(&snapshotReads, 1)
			}
		}
	}()

	writers.Wait()
	close(stop)
	<-readerDone

	snap := l.Snapshot()
	wantPerIP := goroutinesPerIP * failuresPerGoroutine
	for _, ipStr := range ips {
		// Normalize the same way the limiter does so we lookup with the
		// right key (pure IPv6 stays, IPv4 stays, IPv4-mapped IPv6 would
		// collapse — none of the test IPs are mapped).
		key := normalize(mustParseIP(t, ipStr)).String()
		if got := snap[key]; got != wantPerIP {
			t.Errorf("IP %s: fail_count = %d, want %d", key, got, wantPerIP)
		}
	}
	if atomic.LoadInt64(&snapshotReads) == 0 {
		t.Error("snapshot reader never ran — concurrency coverage is weaker than intended")
	}
}

// TestAcquire_PerIPLockSerializesObservations is a tight race-style test:
// two goroutines acquire the same IP "simultaneously" and the per-IP
// lock must ensure the second one observes the failure recorded by the
// first. Without the lock, both could observe fail_count=0 and return
// delay=0 — the bug the spec §5 lock requirement is designed to prevent.
//
// We use a real-time small budget here because the FakeClock advances
// only on demand; the assertion is "the second Acquire's observed delay
// is > 0", which only holds if it waited for the first release.
func TestAcquire_PerIPLockSerializesObservations(t *testing.T) {
	clk := NewFakeClock(time.Unix(0, 0))
	l := New(clk)
	ip := mustParseIP(t, "192.0.2.99")

	// First goroutine: Acquire, hold for a moment, then release(false).
	firstAcquired := make(chan struct{})
	firstReleased := make(chan struct{})
	go func() {
		_, rel := l.Acquire(ip)
		close(firstAcquired)
		// Hold the entry mutex for 25ms so the second goroutine has to
		// block on it.
		time.Sleep(25 * time.Millisecond)
		rel(false)
		close(firstReleased)
	}()

	<-firstAcquired

	// Second goroutine: launches while the first holds the lock. By the
	// time Acquire returns here, the first must have released and bumped
	// fail_count to 1, so the second observes delay=1s.
	start := time.Now()
	delay, rel := l.Acquire(ip)
	waited := time.Since(start)
	rel(true) // cleanup
	<-firstReleased

	if delay != 1*time.Second {
		t.Errorf("second Acquire observed delay = %v, want 1s (first failure should already be recorded)", delay)
	}
	if waited < 20*time.Millisecond {
		t.Errorf("second Acquire returned in %v — appears to have bypassed the per-IP lock", waited)
	}
}
