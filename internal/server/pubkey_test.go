package server

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/mitchellnemitz/minisshd/internal/auth"
	"github.com/mitchellnemitz/minisshd/internal/logging"
)

// generatePubkeyTestKey returns a fresh ed25519 signer for pubkey callback tests.
func generatePubkeyTestKey(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("NewSignerFromKey: %v", err)
	}
	return signer
}

// buildFakeKeysetSourceFromFile creates a real KeysetSource by writing keys to
// a temp file and calling Load. This is the correct approach for unit tests
// that need a populated Keyset without filesystem mocking.
func buildFakeKeysetSourceFromFile(t *testing.T, keys []ssh.PublicKey) *auth.KeysetSource {
	t.Helper()
	dir := t.TempDir()
	var content []byte
	for _, k := range keys {
		content = append(content, ssh.MarshalAuthorizedKey(k)...)
	}
	path := dir + "/authorized_keys"
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatalf("os.WriteFile(%q): %v", path, err)
	}
	ks := auth.NewKeysetSource(path, nopPubkeyLoggerForServer{})
	if err := ks.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	return ks
}

// nopPubkeyLoggerForServer satisfies the pubkeyLogger interface used by KeysetSource.
type nopPubkeyLoggerForServer struct{}

func (nopPubkeyLoggerForServer) PubkeyParseError(_ string, _ int, _ string)    {}
func (nopPubkeyLoggerForServer) PubkeyOptionIgnored(_ string, _ int, _ string) {}
func (nopPubkeyLoggerForServer) PubkeyKeysMissing(_ string)                    {}
func (nopPubkeyLoggerForServer) PubkeyReloadOK(_ string, _ int)                {}
func (nopPubkeyLoggerForServer) PubkeyReloadFailed(_ string, _ string)         {}

// TestPublickeyCallback_SuccessLogsAuthOK_ReleasesTrue mirrors the password
// version: the spec §5 lifecycle must be Acquire → sleep → CheckUsername+Check
// → release(true) → AuthOK.
func TestPublickeyCallback_SuccessLogsAuthOK_ReleasesTrue(t *testing.T) {
	signer := generatePubkeyTestKey(t)
	pub := signer.PublicKey()

	lim := newFakeLimiterWithKey("127.0.0.1")
	creds := &fakeCreds{ok: true, reason: ""}
	src := buildFakeKeysetSourceFromFile(t, []ssh.PublicKey{pub})
	logger := &recordingAuthLogger{}
	sleeper := &recordingSleeper{}

	cb := publickeyCallback(lim, creds, src, logger, sleeper.sleep)
	remote := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 5555}
	meta := fakeConnMetadata{user: "alice", remoteAddr: remote}

	_, err := cb(meta, pub)
	if err != nil {
		t.Fatalf("expected nil error on success, got %v", err)
	}

	wantSeq := []string{"Acquire(127.0.0.1)", "release(true)"}
	if !sliceEqual(lim.calls, wantSeq) {
		t.Fatalf("limiter call sequence = %v, want %v", lim.calls, wantSeq)
	}
	if len(logger.okCalls) != 1 {
		t.Fatalf("expected 1 AuthOK call, got %d", len(logger.okCalls))
	}
	if !strings.Contains(logger.okCalls[0], "publickey") {
		t.Errorf("AuthOK should record method=publickey; got %q", logger.okCalls[0])
	}
	if logger.failCall != nil {
		t.Fatalf("AuthFail must not be called on success: %+v", logger.failCall)
	}
}

// TestPublickeyCallback_BadKeyReleasesFalseLogsBadKey verifies that when the
// username matches but the key is not in the keyset, the callback returns
// release(false) and logs AuthFail with reason=bad-key and the presented fingerprint.
func TestPublickeyCallback_BadKeyReleasesFalseLogsBadKey(t *testing.T) {
	// Accepted key is key1; presented key is key2 (wrong).
	signer1 := generatePubkeyTestKey(t)
	signer2 := generatePubkeyTestKey(t)
	pub1 := signer1.PublicKey()
	pub2 := signer2.PublicKey() // will be presented but not accepted

	lim := newFakeLimiterWithKey("127.0.0.1")
	creds := &fakeCreds{ok: true, reason: ""} // username always OK
	src := buildFakeKeysetSourceFromFile(t, []ssh.PublicKey{pub1})
	logger := &recordingAuthLogger{}
	sleeper := &recordingSleeper{}

	cb := publickeyCallback(lim, creds, src, logger, sleeper.sleep)
	remote := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 5555}
	meta := fakeConnMetadata{user: "alice", remoteAddr: remote}

	_, err := cb(meta, pub2)
	if err == nil {
		t.Fatal("expected non-nil error for wrong key")
	}

	wantSeq := []string{"Acquire(127.0.0.1)", "release(false)"}
	if !sliceEqual(lim.calls, wantSeq) {
		t.Fatalf("limiter call sequence = %v, want %v", lim.calls, wantSeq)
	}
	if logger.failCall == nil {
		t.Fatal("expected AuthFail to be called")
	}
	if logger.failCall.reason != auth.ReasonBadKey {
		t.Errorf("AuthFail reason = %q, want %q", logger.failCall.reason, auth.ReasonBadKey)
	}
	wantFP := ssh.FingerprintSHA256(pub2)
	if logger.failCall.fingerprint != wantFP {
		t.Errorf("AuthFail fingerprint = %q, want %q", logger.failCall.fingerprint, wantFP)
	}
}

// TestPublickeyCallback_BadUserReleasesFalseLogsBadUser verifies that when the
// username does not match, bad-user wins over bad-key in the reason field.
func TestPublickeyCallback_BadUserReleasesFalseLogsBadUser(t *testing.T) {
	signer := generatePubkeyTestKey(t)
	pub := signer.PublicKey()

	lim := newFakeLimiterWithKey("127.0.0.1")
	creds := &fakeCreds{ok: false, reason: auth.ReasonBadUser}
	src := buildFakeKeysetSourceFromFile(t, []ssh.PublicKey{pub})
	logger := &recordingAuthLogger{}
	sleeper := &recordingSleeper{}

	cb := publickeyCallback(lim, creds, src, logger, sleeper.sleep)
	remote := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 5555}
	meta := fakeConnMetadata{user: "mallory", remoteAddr: remote}

	_, err := cb(meta, pub)
	if err == nil {
		t.Fatal("expected non-nil error for bad user")
	}
	if logger.failCall == nil {
		t.Fatal("expected AuthFail to be called")
	}
	if logger.failCall.reason != auth.ReasonBadUser {
		t.Errorf("AuthFail reason = %q, want %q", logger.failCall.reason, auth.ReasonBadUser)
	}
}

// TestPublickeyCallback_SleepHappensBeforeCheck verifies spec §5 ordering:
// Acquire → sleep(delay) → CheckUsername+Check → release.
func TestPublickeyCallback_SleepHappensBeforeCheck(t *testing.T) {
	signer := generatePubkeyTestKey(t)
	pub := signer.PublicKey()

	lim := newFakeLimiterWithKey("127.0.0.1")
	lim.delay = 7 * time.Second
	creds := &fakeCreds{ok: false, reason: auth.ReasonBadUser}
	src := buildFakeKeysetSourceFromFile(t, []ssh.PublicKey{pub})
	logger := &recordingAuthLogger{}

	var sleepObservedCredsCalls int
	sleeper := func(d time.Duration) {
		if d != 7*time.Second {
			t.Errorf("sleeper delay = %v, want 7s", d)
		}
		sleepObservedCredsCalls = creds.calls
	}

	cb := publickeyCallback(lim, creds, src, logger, sleeper)
	remote := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234}
	_, _ = cb(fakeConnMetadata{user: "x", remoteAddr: remote}, pub)

	if sleepObservedCredsCalls != 0 {
		t.Fatalf("sleep ran after CheckUsername (saw %d calls during sleep)", sleepObservedCredsCalls)
	}
}

// TestPublickeyCallback_IPv4MappedV6Normalization verifies that a connection
// arriving on a dual-stack listener (::ffff:127.0.0.1) is normalized to the
// bare IPv4 key when looking up the limiter snapshot.
func TestPublickeyCallback_IPv4MappedV6Normalization(t *testing.T) {
	signer := generatePubkeyTestKey(t)
	pub := signer.PublicKey()

	lim := newFakeLimiterWithKey("127.0.0.1")
	creds := &fakeCreds{ok: false, reason: auth.ReasonBadUser}
	src := buildFakeKeysetSourceFromFile(t, []ssh.PublicKey{pub})
	logger := &recordingAuthLogger{}
	sleeper := &recordingSleeper{}

	cb := publickeyCallback(lim, creds, src, logger, sleeper.sleep)
	mapped := &net.TCPAddr{IP: net.ParseIP("::ffff:127.0.0.1"), Port: 1234}
	_, _ = cb(fakeConnMetadata{user: "x", remoteAddr: mapped}, pub)

	if logger.failCall == nil {
		t.Fatal("expected AuthFail")
	}
	if logger.failCall.attempt != 1 {
		t.Fatalf("attempt = %d; snapshot key was likely not normalized", logger.failCall.attempt)
	}
}

// TestPublickeyCallback_LoggerDoesNotLeakPassword verifies that even for
// publickey flows, the configured password never appears in log output.
func TestPublickeyCallback_LoggerDoesNotLeakPassword(t *testing.T) {
	signer := generatePubkeyTestKey(t)
	pub := signer.PublicKey()

	lim := newFakeLimiterWithKey("127.0.0.1")
	creds := &fakeCreds{ok: true, reason: ""}
	src := buildFakeKeysetSourceFromFile(t, []ssh.PublicKey{pub})

	var buf bytes.Buffer
	realLog := logging.New(&buf, "supersecret123", logging.FormatLogfmt)
	sleeper := &recordingSleeper{}

	cb := publickeyCallback(lim, creds, src, realLog, sleeper.sleep)
	remote := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 5555}
	_, _ = cb(fakeConnMetadata{user: "alice", remoteAddr: remote}, pub)

	if strings.Contains(buf.String(), "supersecret123") {
		t.Fatalf("logger output leaked the password: %q", buf.String())
	}
}

// TestPublickeyCallback_CacheEvictionCausesDoubleAcquire documents the
// cache-size-1 implication (plan Fix D): if a client probes key A (rejected,
// result cached), then probes key B (evicts A from the size-1 cache), then
// signs with key A again — the cache misses on A's second invocation and
// PublicKeyCallback fires a second time for key A. This test verifies that
// across the probe-A → probe-B-evicts-A → sign-A sequence the total Acquire
// count is 3 (once per callback invocation, since Acquire runs unconditionally).
func TestPublickeyCallback_CacheEvictionCausesDoubleAcquire(t *testing.T) {
	signerA := generatePubkeyTestKey(t)
	signerB := generatePubkeyTestKey(t)
	pubA := signerA.PublicKey()
	pubB := signerB.PublicKey()

	// Neither key is accepted — both will be rejected.
	src := buildFakeKeysetSourceFromFile(t, nil)

	lim := newFakeLimiterWithKey("10.0.0.1")
	creds := &fakeCreds{ok: true, reason: ""}
	logger := &recordingAuthLogger{}
	sleeper := &recordingSleeper{}

	cb := publickeyCallback(lim, creds, src, logger, sleeper.sleep)
	remote := &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 9000}
	meta := fakeConnMetadata{user: "alice", remoteAddr: remote}

	// Step 1: probe key A — rejected; the library caches this result for A.
	_, _ = cb(meta, pubA)
	// Step 2: probe key B — rejected; the size-1 cache evicts A's entry.
	_, _ = cb(meta, pubB)
	// Step 3: sign with key A again — cache misses, PublicKeyCallback fires a
	// second time for A. Acquire must run again.
	_, _ = cb(meta, pubA)

	acquireCount := 0
	for _, c := range lim.calls {
		if strings.HasPrefix(c, "Acquire(") {
			acquireCount++
		}
	}
	if acquireCount != 3 {
		t.Errorf("expected 3 Acquire calls (probe-A, probe-B, sign-A re-fire); got %d; calls=%v",
			acquireCount, lim.calls)
	}
}

// TestPublickeyCallback_QueryAndSignBothAcquire documents that both a
// rejected-key probe and a real sign attempt each call Acquire once.
func TestPublickeyCallback_QueryAndSignBothAcquire(t *testing.T) {
	// Rejected key: key is NOT in the keyset.
	signerA := generatePubkeyTestKey(t)
	pubA := signerA.PublicKey()

	// Use an empty keyset so pubA is always rejected.
	src := buildFakeKeysetSourceFromFile(t, nil)

	lim := newFakeLimiterWithKey("127.0.0.1")
	creds := &fakeCreds{ok: true, reason: ""}
	logger := &recordingAuthLogger{}
	sleeper := &recordingSleeper{}

	cb := publickeyCallback(lim, creds, src, logger, sleeper.sleep)
	remote := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 5555}
	meta := fakeConnMetadata{user: "alice", remoteAddr: remote}

	// First invoke: probe — pubA is rejected, Acquire count = 1.
	_, _ = cb(meta, pubA)
	if len(lim.calls) < 2 {
		t.Fatalf("expected at least 2 limiter calls after first probe, got %d: %v", len(lim.calls), lim.calls)
	}

	// Second invoke: same key again (simulates sign attempt or second probe).
	_, _ = cb(meta, pubA)
	acquireCount := 0
	for _, c := range lim.calls {
		if strings.HasPrefix(c, "Acquire(") {
			acquireCount++
		}
	}
	if acquireCount != 2 {
		t.Errorf("Acquire count = %d after two invocations, want 2; calls = %v", acquireCount, lim.calls)
	}
}
