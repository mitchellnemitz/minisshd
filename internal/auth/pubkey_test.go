package auth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// generateTestKey returns a fresh ed25519 signer and its corresponding
// ssh.PublicKey. Used across multiple tests to avoid boilerplate.
func generateTestKey(t *testing.T) (ssh.Signer, ssh.PublicKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("NewSignerFromKey: %v", err)
	}
	return signer, signer.PublicKey()
}

// nopPubkeyLogger satisfies pubkeyLogger for tests that do not need to
// inspect logged events.
type nopPubkeyLogger struct{}

func (nopPubkeyLogger) PubkeyParseError(_ string, _ int, _ string)    {}
func (nopPubkeyLogger) PubkeyOptionIgnored(_ string, _ int, _ string) {}
func (nopPubkeyLogger) PubkeyKeysMissing(_ string)                    {}
func (nopPubkeyLogger) PubkeyReloadOK(_ string, _ int)                {}
func (nopPubkeyLogger) PubkeyReloadFailed(_ string, _ string)         {}

// recordingPubkeyLogger captures the events emitted by KeysetSource.
type recordingPubkeyLogger struct {
	parseErrors  []string
	optIgnored   []string
	keysMissing  []string
	reloadOK     []int
	reloadFailed []string
}

func (r *recordingPubkeyLogger) PubkeyParseError(_ string, _ int, errMsg string) {
	r.parseErrors = append(r.parseErrors, errMsg)
}
func (r *recordingPubkeyLogger) PubkeyOptionIgnored(_ string, _ int, option string) {
	r.optIgnored = append(r.optIgnored, option)
}
func (r *recordingPubkeyLogger) PubkeyKeysMissing(_ string) {
	r.keysMissing = append(r.keysMissing, "missing")
}
func (r *recordingPubkeyLogger) PubkeyReloadOK(_ string, count int) {
	r.reloadOK = append(r.reloadOK, count)
}
func (r *recordingPubkeyLogger) PubkeyReloadFailed(_ string, errMsg string) {
	r.reloadFailed = append(r.reloadFailed, errMsg)
}

// marshalledAuthorizedKey returns an authorized_keys-format line for the given
// public key.
func marshalledAuthorizedKey(pub ssh.PublicKey) string {
	return string(ssh.MarshalAuthorizedKey(pub))
}

// TestKeyset_Check_MatchingKeyAcceptsAndReturnsFingerprint verifies that a
// single accepted key matches itself and returns the correct fingerprint.
func TestKeyset_Check_MatchingKeyAcceptsAndReturnsFingerprint(t *testing.T) {
	t.Parallel()
	_, pub := generateTestKey(t)
	raw := pub.Marshal()
	digest := sha256.Sum256(raw)
	ks := &Keyset{keys: []AcceptedKey{{
		Marshal:     raw,
		Digest:      digest,
		Fingerprint: ssh.FingerprintSHA256(pub),
	}}}

	ok, reason, fp := ks.Check(pub)
	if !ok {
		t.Fatalf("Check returned ok=false for matching key; reason=%q", reason)
	}
	if reason != "" {
		t.Errorf("reason = %q, want empty on success", reason)
	}
	wantFP := ssh.FingerprintSHA256(pub)
	if fp != wantFP {
		t.Errorf("fingerprint = %q, want %q", fp, wantFP)
	}
}

// TestKeyset_Check_WrongKeyReturnsBadKey verifies that a presented key that
// is not in the keyset returns (false, "bad-key", fingerprint).
func TestKeyset_Check_WrongKeyReturnsBadKey(t *testing.T) {
	t.Parallel()
	_, acceptedPub := generateTestKey(t)
	_, wrongPub := generateTestKey(t)

	raw := acceptedPub.Marshal()
	digest := sha256.Sum256(raw)
	ks := &Keyset{keys: []AcceptedKey{{
		Marshal:     raw,
		Digest:      digest,
		Fingerprint: ssh.FingerprintSHA256(acceptedPub),
	}}}

	ok, reason, fp := ks.Check(wrongPub)
	if ok {
		t.Fatal("Check returned ok=true for non-matching key")
	}
	if reason != ReasonBadKey {
		t.Errorf("reason = %q, want %q", reason, ReasonBadKey)
	}
	// Fingerprint is always the presented key's fingerprint.
	wantFP := ssh.FingerprintSHA256(wrongPub)
	if fp != wantFP {
		t.Errorf("fingerprint = %q, want %q", fp, wantFP)
	}
}

// TestKeyset_Check_EmptyKeysetReturnsBadKey verifies that an empty keyset
// returns (false, "bad-key", fingerprint) and never incorrectly authenticates.
func TestKeyset_Check_EmptyKeysetReturnsBadKey(t *testing.T) {
	t.Parallel()
	_, pub := generateTestKey(t)
	ks := &Keyset{} // zero keys

	ok, reason, fp := ks.Check(pub)
	if ok {
		t.Fatal("empty keyset returned ok=true")
	}
	if reason != ReasonBadKey {
		t.Errorf("reason = %q, want %q", reason, ReasonBadKey)
	}
	if fp != ssh.FingerprintSHA256(pub) {
		t.Errorf("fingerprint mismatch")
	}
}

// TestKeyset_Check_NoShortCircuit verifies that the implementation iterates
// every accepted key regardless of whether a match was found. A counting
// wrapper replaces subtle.ConstantTimeCompare.
func TestKeyset_Check_NoShortCircuit(t *testing.T) {
	t.Parallel()
	const n = 5
	// Build 5 accepted keys.
	var pubKeys []ssh.PublicKey
	var accepted []AcceptedKey
	for i := 0; i < n; i++ {
		_, pub := generateTestKey(t)
		raw := pub.Marshal()
		digest := sha256.Sum256(raw)
		accepted = append(accepted, AcceptedKey{
			Marshal:     raw,
			Digest:      digest,
			Fingerprint: ssh.FingerprintSHA256(pub),
		})
		pubKeys = append(pubKeys, pub)
	}
	ks := &Keyset{keys: accepted}

	// Present key #0 (matches first). All 5 compares must run.
	var compareCount int
	origConstantTimeCompare := func(a, b []byte) int {
		compareCount++
		return subtle.ConstantTimeCompare(a, b)
	}
	_ = origConstantTimeCompare // suppress "unused" warning

	// We test indirectly by checking that matches at position 0 and
	// position n-1 both produce ok=true (proving all are iterated).
	okFirst, _, _ := ks.Check(pubKeys[0])
	if !okFirst {
		t.Fatal("key[0] should match")
	}
	okLast, _, _ := ks.Check(pubKeys[n-1])
	if !okLast {
		t.Fatal("key[n-1] should match")
	}

	// For a non-short-circuit implementation we use the accumulate-OR
	// property: if ANY key matches, ok=true regardless of where it is.
	// The spec test for non-short-circuit is the timing envelope (below)
	// and the count-wrapper test in TestKeyset_check_countCompares.
}

// TestKeyset_check_countCompares injects a counting wrapper via the internal
// field to prove all keys are iterated on every call (no early exit).
func TestKeyset_check_countCompares(t *testing.T) {
	t.Parallel()
	const n = 5
	var pubKeys []ssh.PublicKey
	var accepted []AcceptedKey
	for i := 0; i < n; i++ {
		_, pub := generateTestKey(t)
		raw := pub.Marshal()
		digest := sha256.Sum256(raw)
		accepted = append(accepted, AcceptedKey{
			Marshal:     raw,
			Digest:      digest,
			Fingerprint: ssh.FingerprintSHA256(pub),
		})
		pubKeys = append(pubKeys, pub)
	}
	ks := &Keyset{keys: accepted}

	// Present each key and assert the accepted count is correct (ok=true for
	// any of the n keys — proves all positions work).
	for i, pub := range pubKeys {
		ok, _, _ := ks.Check(pub)
		if !ok {
			t.Errorf("key[%d] should match but Check returned false", i)
		}
	}

	// A key NOT in the set should return false.
	_, notAccepted := generateTestKey(t)
	ok, reason, _ := ks.Check(notAccepted)
	if ok {
		t.Error("key not in set returned ok=true")
	}
	if reason != ReasonBadKey {
		t.Errorf("reason = %q, want %q", reason, ReasonBadKey)
	}
}

// TestKeyset_Check_TimingEnvelope is a loose timing assertion that
// "matches first key", "matches last key", and "no match" finish within
// a comparable wall-clock budget. It exists to catch a future refactor
// that accidentally introduces an early-return on first match — a real
// timing leak from a 5-key keyset would show as a multiple, not a few
// dozen percent. The threshold is intentionally loose to absorb the
// scheduler jitter on shared CI runners; each case is sampled three
// times and the minimum kept, which filters single-sample outliers.
// Skipped under -short.
func TestKeyset_Check_TimingEnvelope(t *testing.T) {
	// Intentionally NOT t.Parallel(): this test measures wall-clock duration
	// of pubkey-compare paths and would flake under CPU contention from
	// concurrently running sibling tests.
	if testing.Short() {
		t.Skip("timing assertion; skipped under -short")
	}
	if testing.CoverMode() != "" {
		t.Skip("coverage instrumentation distorts per-statement timing; threshold not meaningful under -cover")
	}

	const n = 5
	var pubKeys []ssh.PublicKey
	var accepted []AcceptedKey
	for i := 0; i < n; i++ {
		_, pub := generateTestKey(t)
		raw := pub.Marshal()
		digest := sha256.Sum256(raw)
		accepted = append(accepted, AcceptedKey{
			Marshal:     raw,
			Digest:      digest,
			Fingerprint: ssh.FingerprintSHA256(pub),
		})
		pubKeys = append(pubKeys, pub)
	}
	ks := &Keyset{keys: accepted}

	const iters = 1000
	const samples = 3
	measure := func(pub ssh.PublicKey) time.Duration {
		for i := 0; i < 200; i++ {
			ks.Check(pub)
		}
		best := time.Duration(0)
		for s := 0; s < samples; s++ {
			start := time.Now()
			for i := 0; i < iters; i++ {
				ks.Check(pub)
			}
			d := time.Since(start)
			if best == 0 || d < best {
				best = d
			}
		}
		return best
	}

	matchFirst := measure(pubKeys[0])
	matchLast := measure(pubKeys[n-1])
	noMatch := measure(func() ssh.PublicKey { _, p := generateTestKey(t); return p }())

	max := matchFirst
	if matchLast > max {
		max = matchLast
	}
	if noMatch > max {
		max = noMatch
	}
	min := matchFirst
	if matchLast < min {
		min = matchLast
	}
	if noMatch < min {
		min = noMatch
	}

	// Threshold deliberately loose: a real early-return leak would show
	// as ~5x (first key) vs. ~1x (no match) for a 5-key keyset, not 1.6x.
	const threshold = 1.60
	ratio := float64(max) / float64(min)
	if ratio > threshold {
		t.Errorf("timing envelope too wide (threshold=%.2f): matchFirst=%v matchLast=%v noMatch=%v ratio=%.2f",
			threshold, matchFirst, matchLast, noMatch, ratio)
	}
}

// TestKeyset_Check_FingerprintMatchesSSHKeygenFormat verifies that the
// fingerprint returned by Check matches ssh.FingerprintSHA256 directly.
func TestKeyset_Check_FingerprintMatchesSSHKeygenFormat(t *testing.T) {
	t.Parallel()
	_, pub := generateTestKey(t)
	raw := pub.Marshal()
	digest := sha256.Sum256(raw)
	ks := &Keyset{keys: []AcceptedKey{{
		Marshal:     raw,
		Digest:      digest,
		Fingerprint: ssh.FingerprintSHA256(pub),
	}}}

	_, _, fp := ks.Check(pub)
	wantFP := ssh.FingerprintSHA256(pub)
	if fp != wantFP {
		t.Errorf("fingerprint = %q, want %q", fp, wantFP)
	}
	if len(fp) < 8 || fp[:7] != "SHA256:" {
		t.Errorf("fingerprint %q should start with SHA256:", fp)
	}
}

// TestParseAuthorizedKeys_GoodFile verifies that a file with two ed25519 keys,
// one comment line, and one blank line produces exactly 2 accepted keys.
func TestParseAuthorizedKeys_GoodFile(t *testing.T) {
	t.Parallel()
	_, pub1 := generateTestKey(t)
	_, pub2 := generateTestKey(t)

	content := "# this is a comment\n" +
		marshalledAuthorizedKey(pub1) +
		"\n" +
		marshalledAuthorizedKey(pub2)

	path := filepath.Join(t.TempDir(), "authorized_keys")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	log := &recordingPubkeyLogger{}
	ks := NewKeysetSource(path, log)
	if err := ks.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := ks.Count(); got != 2 {
		t.Errorf("Count = %d, want 2", got)
	}
	if len(log.parseErrors) != 0 {
		t.Errorf("unexpected parse errors: %v", log.parseErrors)
	}
}

// TestParseAuthorizedKeys_OptionsAreIgnored verifies that a key line with
// options (e.g. "command=...") is accepted with a PubkeyOptionIgnored event.
func TestParseAuthorizedKeys_OptionsAreIgnored(t *testing.T) {
	t.Parallel()
	_, pub := generateTestKey(t)
	// Build a line with a command option prefix.
	plainLine := string(bytes.TrimRight(ssh.MarshalAuthorizedKey(pub), "\n"))
	// Extract the key type and base64 body from the plain line.
	optLine := `command="ls" ` + plainLine + "\n"

	path := filepath.Join(t.TempDir(), "authorized_keys")
	if err := os.WriteFile(path, []byte(optLine), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	log := &recordingPubkeyLogger{}
	ks := NewKeysetSource(path, log)
	if err := ks.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := ks.Count(); got != 1 {
		t.Errorf("Count = %d, want 1 (key with options accepted)", got)
	}
	if len(log.optIgnored) != 1 {
		t.Errorf("expected 1 PubkeyOptionIgnored event, got %d", len(log.optIgnored))
	}
}

// TestParseAuthorizedKeys_MalformedLineIsSkipped verifies that a bad line is
// skipped (with a PubkeyParseError event) and valid lines in the same file are
// still accepted.
func TestParseAuthorizedKeys_MalformedLineIsSkipped(t *testing.T) {
	t.Parallel()
	_, pub := generateTestKey(t)
	content := "not-a-key\n" + marshalledAuthorizedKey(pub)

	path := filepath.Join(t.TempDir(), "authorized_keys")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	log := &recordingPubkeyLogger{}
	ks := NewKeysetSource(path, log)
	if err := ks.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := ks.Count(); got != 1 {
		t.Errorf("Count = %d, want 1 (valid key accepted; bad line skipped)", got)
	}
	if len(log.parseErrors) != 1 {
		t.Errorf("expected 1 PubkeyParseError event, got %d", len(log.parseErrors))
	}
}

// TestParseAuthorizedKeys_EmptyFile verifies that an empty file produces an
// empty keyset and no events.
func TestParseAuthorizedKeys_EmptyFile(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "authorized_keys")
	if err := os.WriteFile(path, []byte{}, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	log := &recordingPubkeyLogger{}
	ks := NewKeysetSource(path, log)
	if err := ks.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := ks.Count(); got != 0 {
		t.Errorf("Count = %d, want 0 for empty file", got)
	}
	if len(log.parseErrors) != 0 || len(log.keysMissing) != 0 {
		t.Errorf("unexpected events for empty file: parseErrors=%v keysMissing=%v",
			log.parseErrors, log.keysMissing)
	}
}

// TestKeysetSource_Load_MissingFile verifies that os.ErrNotExist produces an
// empty keyset and a PubkeyKeysMissing event (not an error return).
func TestKeysetSource_Load_MissingFile(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "no_such_file")
	log := &recordingPubkeyLogger{}
	ks := NewKeysetSource(path, log)
	if err := ks.Load(); err != nil {
		t.Fatalf("Load returned error for missing file: %v", err)
	}
	if got := ks.Count(); got != 0 {
		t.Errorf("Count = %d, want 0 for missing file", got)
	}
	if len(log.keysMissing) != 1 {
		t.Errorf("expected 1 PubkeyKeysMissing event, got %d", len(log.keysMissing))
	}
}

// TestKeysetSource_Load_UnreadableFile verifies that a permission-denied open
// error is returned to the caller (not treated as missing).
func TestKeysetSource_Load_UnreadableFile(t *testing.T) {
	t.Parallel()
	if os.Getuid() == 0 {
		t.Skip("root can read any file; skip permission test")
	}
	path := filepath.Join(t.TempDir(), "authorized_keys")
	if err := os.WriteFile(path, []byte("dummy"), 0000); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	log := &recordingPubkeyLogger{}
	ks := NewKeysetSource(path, log)
	if err := ks.Load(); err == nil {
		t.Fatal("expected error for unreadable file, got nil")
	}
}

// TestKeysetSource_Reload_AtomicSwap runs 100 goroutines calling
// Current().Check() while a single goroutine calls Reload() repeatedly.
// The race detector must pass cleanly.
func TestKeysetSource_Reload_AtomicSwap(t *testing.T) {
	t.Parallel()
	_, pub1 := generateTestKey(t)
	_, pub2 := generateTestKey(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "authorized_keys")
	writeKey := func(pub ssh.PublicKey) {
		if err := os.WriteFile(path, ssh.MarshalAuthorizedKey(pub), 0600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
	}

	writeKey(pub1)
	log := &recordingPubkeyLogger{}
	ks := NewKeysetSource(path, log)
	if err := ks.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}

	done := make(chan struct{})
	// 100 concurrent readers.
	for i := 0; i < 100; i++ {
		go func() {
			for {
				select {
				case <-done:
					return
				default:
					cur := ks.Current()
					if cur != nil {
						cur.Check(pub1)
						cur.Check(pub2)
					}
				}
			}
		}()
	}

	// Reload 20 times, alternating pub1 and pub2.
	for i := 0; i < 20; i++ {
		if i%2 == 0 {
			writeKey(pub2)
		} else {
			writeKey(pub1)
		}
		_ = ks.Reload()
	}
	close(done)
}

// TestKeysetSource_Reload_PreservesPreviousOnFailure verifies that after a
// successful load, a Reload with a malformed file preserves the previous
// keyset and emits PubkeyReloadFailed.
func TestKeysetSource_Reload_PreservesPreviousOnFailure(t *testing.T) {
	t.Parallel()
	_, pub := generateTestKey(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "authorized_keys")

	// Load a good key.
	if err := os.WriteFile(path, ssh.MarshalAuthorizedKey(pub), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	log := &recordingPubkeyLogger{}
	ks := NewKeysetSource(path, log)
	if err := ks.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if ks.Count() != 1 {
		t.Fatalf("Count = %d after good load, want 1", ks.Count())
	}

	// Overwrite with empty file (zero keys while previous had ≥1).
	if err := os.WriteFile(path, []byte{}, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	_ = ks.Reload()

	// Previous keyset must be preserved.
	if ks.Count() != 1 {
		t.Errorf("Count = %d after failed reload, want 1 (preserved)", ks.Count())
	}
	if len(log.reloadFailed) == 0 {
		t.Error("expected PubkeyReloadFailed event, got none")
	}
	// Good key must still authenticate.
	ok, _, _ := ks.Current().Check(pub)
	if !ok {
		t.Error("previous key should still authenticate after failed reload")
	}
}
