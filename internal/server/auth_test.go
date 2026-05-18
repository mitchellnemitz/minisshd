package server

import (
	"bytes"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mitchellnemitz/minissh/internal/auth"
	"github.com/mitchellnemitz/minissh/internal/logging"
)

// fakeConnMetadata is a minimal ssh.ConnMetadata for password-callback
// tests. Only the methods the callback reads are non-trivial; the rest
// return zero values.
type fakeConnMetadata struct {
	user       string
	remoteAddr net.Addr
}

func (f fakeConnMetadata) User() string          { return f.user }
func (f fakeConnMetadata) SessionID() []byte     { return nil }
func (f fakeConnMetadata) ClientVersion() []byte { return nil }
func (f fakeConnMetadata) ServerVersion() []byte { return nil }
func (f fakeConnMetadata) RemoteAddr() net.Addr  { return f.remoteAddr }
func (f fakeConnMetadata) LocalAddr() net.Addr   { return nil }

// fakeLimiter records the sequence of Acquire/release calls a test makes
// so the assertions can prove the spec §5 ordering. It also satisfies
// Snapshot so the auth-fail logging path can read attempt counts.
//
// lastIPKey is the normalized IP string the callback will look up in
// Snapshot(); tests pre-populate it so a single-key map can be returned
// without re-implementing normalization here.
type fakeLimiter struct {
	mu         sync.Mutex
	calls      []string
	delay      time.Duration
	failCount  int
	releaseArg *bool
	lastIPKey  string
}

func (f *fakeLimiter) Acquire(ip net.IP) (time.Duration, func(success bool)) {
	f.mu.Lock()
	f.calls = append(f.calls, "Acquire("+ip.String()+")")
	d := f.delay
	f.mu.Unlock()
	return d, func(success bool) {
		f.mu.Lock()
		f.releaseArg = &success
		f.calls = append(f.calls, releaseLabel(success))
		if !success {
			f.failCount++
		} else {
			f.failCount = 0
		}
		f.mu.Unlock()
	}
}

func releaseLabel(ok bool) string {
	if ok {
		return "release(true)"
	}
	return "release(false)"
}

func (f *fakeLimiter) Snapshot() map[string]int {
	f.mu.Lock()
	defer f.mu.Unlock()
	// The callback normalizes the IP itself before lookup; mirror the
	// limiter's behavior here by keying under the *latest* Acquire IP.
	out := map[string]int{}
	// The callback's lookup key is the normalized IP string. Tests
	// inject IPs via the fakeConnMetadata; we expose a fixed slot.
	out[f.lastIPKey] = f.failCount
	return out
}

type fakeCreds struct {
	ok     bool
	reason string
	calls  int
	mu     sync.Mutex
}

func (c *fakeCreds) Check(user, password string) (bool, string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	return c.ok, c.reason
}

type recordingAuthLogger struct {
	mu       sync.Mutex
	okCalls  []string
	failCall *failEntry
}

type failEntry struct {
	remote, user, reason string
	attempt              int
	nextDelay            time.Duration
}

func (r *recordingAuthLogger) AuthOK(remote, user string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.okCalls = append(r.okCalls, remote+":"+user)
}

func (r *recordingAuthLogger) AuthFail(remote, user, reason string, attempt int, nextDelay time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failCall = &failEntry{remote, user, reason, attempt, nextDelay}
}

// recordingSleeper records every Sleep duration so tests can confirm
// the rate-limit delay is honored before the credential check runs.
type recordingSleeper struct {
	mu        sync.Mutex
	durations []time.Duration
}

func (s *recordingSleeper) sleep(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.durations = append(s.durations, d)
}

func newFakeLimiterWithKey(key string) *fakeLimiter {
	return &fakeLimiter{lastIPKey: key}
}

func TestPasswordCallback_SuccessLogsAuthOK_ReleasesTrue(t *testing.T) {
	lim := newFakeLimiterWithKey("127.0.0.1")
	lim.delay = 0
	creds := &fakeCreds{ok: true, reason: ""}
	logger := &recordingAuthLogger{}
	sleeper := &recordingSleeper{}

	cb := passwordCallback(lim, creds, logger, sleeper.sleep)
	remote := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 5555}
	_, err := cb(fakeConnMetadata{user: "alice", remoteAddr: remote}, []byte("hunter2"))
	if err != nil {
		t.Fatalf("expected nil error on success, got %v", err)
	}

	wantSeq := []string{"Acquire(127.0.0.1)", "release(true)"}
	if !sliceEqual(lim.calls, wantSeq) {
		t.Fatalf("limiter call sequence = %v, want %v", lim.calls, wantSeq)
	}
	if creds.calls != 1 {
		t.Fatalf("creds.Check calls = %d, want 1", creds.calls)
	}
	if got := len(logger.okCalls); got != 1 || !strings.Contains(logger.okCalls[0], "alice") {
		t.Fatalf("expected AuthOK with alice, got %v", logger.okCalls)
	}
	if logger.failCall != nil {
		t.Fatalf("AuthFail must not be called on success: %+v", logger.failCall)
	}
}

func TestPasswordCallback_FailureLogsBadUser_ReleasesFalse(t *testing.T) {
	lim := newFakeLimiterWithKey("10.0.0.5")
	lim.delay = 0
	creds := &fakeCreds{ok: false, reason: auth.ReasonBadUser}
	logger := &recordingAuthLogger{}
	sleeper := &recordingSleeper{}

	cb := passwordCallback(lim, creds, logger, sleeper.sleep)
	remote := &net.TCPAddr{IP: net.ParseIP("10.0.0.5"), Port: 9999}
	_, err := cb(fakeConnMetadata{user: "bob", remoteAddr: remote}, []byte("nope"))
	if err == nil {
		t.Fatal("expected non-nil error on failure")
	}

	wantSeq := []string{"Acquire(10.0.0.5)", "release(false)"}
	if !sliceEqual(lim.calls, wantSeq) {
		t.Fatalf("limiter call sequence = %v, want %v", lim.calls, wantSeq)
	}
	if logger.failCall == nil {
		t.Fatal("expected AuthFail to be called")
	}
	if logger.failCall.reason != "bad-user" {
		t.Fatalf("AuthFail reason = %q, want bad-user", logger.failCall.reason)
	}
	if logger.failCall.user != "bob" {
		t.Fatalf("AuthFail user = %q, want bob", logger.failCall.user)
	}
	if logger.failCall.attempt != 1 {
		t.Fatalf("AuthFail attempt = %d, want 1", logger.failCall.attempt)
	}
	// fail_count = 1 → next_delay = 1s
	if logger.failCall.nextDelay != time.Second {
		t.Fatalf("AuthFail next_delay = %v, want 1s", logger.failCall.nextDelay)
	}
}

func TestPasswordCallback_FailureLogsBadPassword(t *testing.T) {
	lim := newFakeLimiterWithKey("10.0.0.5")
	creds := &fakeCreds{ok: false, reason: auth.ReasonBadPassword}
	logger := &recordingAuthLogger{}
	sleeper := &recordingSleeper{}

	cb := passwordCallback(lim, creds, logger, sleeper.sleep)
	remote := &net.TCPAddr{IP: net.ParseIP("10.0.0.5"), Port: 9999}
	_, _ = cb(fakeConnMetadata{user: "alice", remoteAddr: remote}, []byte("wrong"))
	if logger.failCall == nil {
		t.Fatal("expected AuthFail to be called")
	}
	if logger.failCall.reason != "bad-password" {
		t.Fatalf("AuthFail reason = %q, want bad-password", logger.failCall.reason)
	}
}

func TestPasswordCallback_SleepHappensBeforeCheck(t *testing.T) {
	// Order of operations: Acquire → sleep(delay) → Check → release.
	// We confirm by setting a non-zero delay and a custom sleeper that
	// captures whether Check has been called by the time sleep is invoked.
	lim := newFakeLimiterWithKey("127.0.0.1")
	lim.delay = 7 * time.Second
	creds := &fakeCreds{ok: false, reason: auth.ReasonBadPassword}
	logger := &recordingAuthLogger{}

	var sleepObservedCheckCalls int
	sleeper := func(d time.Duration) {
		if d != 7*time.Second {
			t.Errorf("sleeper delay = %v, want 7s", d)
		}
		sleepObservedCheckCalls = creds.calls
	}

	cb := passwordCallback(lim, creds, logger, sleeper)
	remote := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234}
	_, _ = cb(fakeConnMetadata{user: "x", remoteAddr: remote}, []byte("y"))

	if sleepObservedCheckCalls != 0 {
		t.Fatalf("sleep ran after Check (saw %d calls during sleep); spec §5 requires sleep before callback",
			sleepObservedCheckCalls)
	}
	if creds.calls != 1 {
		t.Fatalf("expected exactly one Check call, got %d", creds.calls)
	}
}

func TestPasswordCallback_IPv4MappedV6Normalization(t *testing.T) {
	// A connection arriving on a dual-stack listener has RemoteAddr.IP
	// equal to ::ffff:127.0.0.1. The callback must look up the snapshot
	// under the normalized "127.0.0.1" key, not the v6-mapped form.
	lim := newFakeLimiterWithKey("127.0.0.1")
	creds := &fakeCreds{ok: false, reason: auth.ReasonBadPassword}
	logger := &recordingAuthLogger{}
	sleeper := &recordingSleeper{}

	cb := passwordCallback(lim, creds, logger, sleeper.sleep)
	mapped := &net.TCPAddr{IP: net.ParseIP("::ffff:127.0.0.1"), Port: 1234}
	_, _ = cb(fakeConnMetadata{user: "x", remoteAddr: mapped}, []byte("y"))

	if logger.failCall == nil {
		t.Fatal("expected AuthFail")
	}
	if logger.failCall.attempt != 1 {
		t.Fatalf("attempt = %d; snapshot key was likely not normalized", logger.failCall.attempt)
	}
}

func TestPasswordCallback_AuthOKDoesNotLeakPasswordToLogger(t *testing.T) {
	// Defense-in-depth: even though our recordingAuthLogger captures
	// fields directly, route through a real *logging.Logger and check
	// that the password substring never appears in the output. Spec §9.
	lim := newFakeLimiterWithKey("127.0.0.1")
	creds := &fakeCreds{ok: true, reason: ""}
	var buf bytes.Buffer
	realLog := logging.New(&buf, "supersecret123")
	sleeper := &recordingSleeper{}

	cb := passwordCallback(lim, creds, realLog, sleeper.sleep)
	remote := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 5555}
	_, _ = cb(fakeConnMetadata{user: "alice", remoteAddr: remote}, []byte("supersecret123"))

	if strings.Contains(buf.String(), "supersecret123") {
		t.Fatalf("logger output leaked the password: %q", buf.String())
	}
}

func TestNextDelay_MatchesSpecSequence(t *testing.T) {
	// Spec §5: 1s, 2s, 4s, 8s, 16s, 32s, 60s (cap), 60s.
	cases := []struct {
		failCount int
		want      time.Duration
	}{
		{0, 0},
		{1, 1 * time.Second},
		{2, 2 * time.Second},
		{3, 4 * time.Second},
		{4, 8 * time.Second},
		{5, 16 * time.Second},
		{6, 32 * time.Second},
		{7, 60 * time.Second},
		{20, 60 * time.Second},
	}
	for _, tc := range cases {
		if got := nextDelay(tc.failCount); got != tc.want {
			t.Errorf("nextDelay(%d) = %v, want %v", tc.failCount, got, tc.want)
		}
	}
}

func TestExtractIP_TCPAddr(t *testing.T) {
	ip := extractIP(&net.TCPAddr{IP: net.ParseIP("198.51.100.7"), Port: 22})
	if ip.String() != "198.51.100.7" {
		t.Fatalf("extractIP = %v, want 198.51.100.7", ip)
	}
}

func sliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
