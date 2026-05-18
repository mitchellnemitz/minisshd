package ratelimit_test

import (
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// Integration tests for the rate limiter drive the in-process server with
// a real clock so cross-connection backoff is observable end-to-end.

// dialWrong attempts an ssh.Dial with one wrong-password attempt against
// addr. It expects failure and returns the wall-clock duration of the
// failed handshake. Tests that need to count fails use this.
func dialWrong(t *testing.T, addr, user string) time.Duration {
	t.Helper()
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password("nope-not-the-password")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         120 * time.Second,
	}
	start := time.Now()
	_, err := ssh.Dial("tcp", addr, cfg)
	if err == nil {
		t.Fatalf("expected wrong-password Dial to fail")
	}
	return time.Since(start)
}

// dialCorrect performs an ssh.Dial with the correct credentials and
// returns the duration plus the (closing) client.
func dialCorrect(t *testing.T, addr, user, password string) (*ssh.Client, time.Duration) {
	t.Helper()
	cfg := clientConfig(user, password)
	start := time.Now()
	cli, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	return cli, time.Since(start)
}

// TestIntegration_BackoffAcrossReconnects is the slow ~16 s timing test
// from spec §13.3/§13.6: five sequential failed connections from one IP,
// then a sixth with correct credentials whose auth-ok must land in
// [13 s, 21 s] from the start of the sixth TCP handshake.
func TestIntegration_BackoffAcrossReconnects(t *testing.T) {
	if testing.Short() {
		t.Skip("slow ~16 s backoff timing test; skipped under -short")
	}

	ts := startTestServer(t, testServerOptions{})
	defer ts.cleanup()

	// 5 wrong-password attempts, each a fresh TCP connection.
	for i := 1; i <= 5; i++ {
		dialWrong(t, ts.addr, ts.user)
	}

	// 6th connection: correct credentials. Expected delay ≈ 16 s.
	_, d := dialCorrect(t, ts.addr, ts.user, ts.password)
	if d < 13*time.Second || d > 21*time.Second {
		t.Fatalf("expected 6th auth to take 13–21s (backoff ~16s); got %s", d)
	}
	if !waitForLog(t, ts.logBuf, "auth-ok", 2*time.Second) {
		t.Fatalf("expected auth-ok in log after 6th connection")
	}
}

// TestIntegration_SuccessfulAuthResetsBackoffCounter exercises the §5
// Reset rule: after a successful auth the per-IP counter clears, so the
// next attempt sees zero delay.
func TestIntegration_SuccessfulAuthResetsBackoffCounter(t *testing.T) {
	if testing.Short() {
		t.Skip("slow timing test; skipped under -short")
	}
	ts := startTestServer(t, testServerOptions{})
	defer ts.cleanup()

	// Three wrong attempts to seed the counter (delays 0, 1, 2 → ~3 s total).
	for i := 0; i < 3; i++ {
		dialWrong(t, ts.addr, ts.user)
	}

	// Sanity: snapshot shows the IP with count > 0.
	snap := ts.limiter.Snapshot()
	if snap["127.0.0.1"] == 0 {
		t.Fatalf("expected fail_count > 0 for 127.0.0.1; got %+v", snap)
	}

	// Successful login resets the counter.
	cli, _ := dialCorrect(t, ts.addr, ts.user, ts.password)
	_ = cli.Close()

	// Wait for the limiter to register the success.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := ts.limiter.Snapshot()["127.0.0.1"]; !ok {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	// Next correct connection must be fast (no delay).
	_, d := dialCorrect(t, ts.addr, ts.user, ts.password)
	if d > 1*time.Second {
		t.Fatalf("expected subsequent auth to be < 1s after reset; got %s", d)
	}
}

// TestIntegration_IPv4MappedIPv6NormalizationSharesCounter verifies that
// IPv4 connections arriving over a dual-stack listener as
// ::ffff:127.0.0.1 are normalized to the bare 127.0.0.1 key, so the
// attacker cannot double their attempt budget. Pure IPv6 (::1) gets its
// own key.
func TestIntegration_IPv4MappedIPv6NormalizationSharesCounter(t *testing.T) {
	if !ipv6Available(t) {
		t.Skip("IPv6 dual-stack unavailable")
	}
	// Bind to ::; the listen helper in cmd/minissh sets IPV6_V6ONLY=0, but
	// in this in-process harness we use net.Listen which defaults to dual-
	// stack on Linux unless /proc/sys/net/ipv6/bindv6only says otherwise.
	ts := startTestServer(t, testServerOptions{bind: "::"})
	defer ts.cleanup()

	_, port, err := net.SplitHostPort(ts.addr)
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}

	// Helper: dial a wrong-password attempt from a chosen source family.
	dialFromAddr := func(network, target string) {
		cfg := &ssh.ClientConfig{
			User:            ts.user,
			Auth:            []ssh.AuthMethod{ssh.Password("nope")},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         30 * time.Second,
		}
		// Use net.Dial to force the source family (Go normally picks one),
		// then upgrade with ssh.NewClientConn.
		conn, err := net.DialTimeout(network, target, 10*time.Second)
		if err != nil {
			t.Fatalf("net.Dial(%s, %s): %v", network, target, err)
		}
		// Best-effort SSH handshake; expected to fail at auth.
		clientConn, chs, reqs, hsErr := ssh.NewClientConn(conn, target, cfg)
		if hsErr == nil {
			ssh.NewClient(clientConn, chs, reqs).Close()
			t.Fatalf("expected wrong-password handshake to fail")
		}
	}

	// IPv4 attempt #1.
	dialFromAddr("tcp4", net.JoinHostPort("127.0.0.1", port))
	// Allow the limiter release(false) to land.
	time.Sleep(100 * time.Millisecond)

	snap := ts.limiter.Snapshot()
	if _, ok := snap["::ffff:127.0.0.1"]; ok {
		t.Fatalf("expected NO ::ffff:127.0.0.1 key (should be normalized); got %+v", snap)
	}
	if snap["127.0.0.1"] != 1 {
		t.Fatalf("expected 127.0.0.1 fail_count=1; got %+v", snap)
	}

	// IPv4 attempt #2 — same key, count goes to 2.
	dialFromAddr("tcp4", net.JoinHostPort("127.0.0.1", port))
	time.Sleep(100 * time.Millisecond)
	snap = ts.limiter.Snapshot()
	if snap["127.0.0.1"] != 2 {
		t.Fatalf("expected 127.0.0.1 fail_count=2; got %+v", snap)
	}

	// Pure IPv6 ::1 — separate key.
	dialFromAddr("tcp6", net.JoinHostPort("::1", port))
	time.Sleep(100 * time.Millisecond)
	snap = ts.limiter.Snapshot()
	if snap["::1"] != 1 {
		t.Fatalf("expected ::1 fail_count=1; got %+v", snap)
	}
	if snap["127.0.0.1"] != 2 {
		t.Fatalf("expected 127.0.0.1 fail_count still 2 after ::1 attempt; got %+v", snap)
	}
}

// ipv6Available probes whether ::1 is dialable so we can decide to skip
// the dual-stack test.
func ipv6Available(t *testing.T) bool {
	t.Helper()
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		// Differentiate ENETUNREACH-style absences for the log; either way
		// we report unavailable.
		t.Logf("IPv6 listen probe failed: %v", err)
		return false
	}
	_ = ln.Close()
	return true
}

// Suppress unused-import warnings on builds that prune dead code; some
// helpers above are conditionally used.
var (
	_ = errors.New
	_ = strings.Contains
)
