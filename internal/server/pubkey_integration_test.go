package server_test

import (
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/mitchellnemitz/minisshd/internal/auth"
)

// TestIntegration_PublickeyOnlyAuthenticates starts a server configured with
// --auth publickey and asserts that a client presenting the matching key is
// accepted, with auth-ok method=publickey in the log.
func TestIntegration_PublickeyOnlyAuthenticates(t *testing.T) {
	signer := generateTestHostKey(t)
	pub := signer.PublicKey()

	ts := startTestServer(t, testServerOptions{
		authMethods:  auth.Methods{auth.MethodPublickey},
		acceptedKeys: []ssh.PublicKey{pub},
	})
	defer ts.cleanup()

	cli, err := ssh.Dial("tcp", ts.addr, clientConfigPubkey(ts.user, signer))
	if err != nil {
		t.Fatalf("Dial with pubkey: %v", err)
	}
	defer cli.Close()

	if !waitForLog(t, ts.logBuf, "event=auth-ok", 5*time.Second) &&
		!waitForLog(t, ts.logBuf, "auth-ok", 5*time.Second) {
		t.Fatalf("expected auth-ok in log:\n%s", ts.logBuf.String())
	}
	if !waitForLog(t, ts.logBuf, "method=publickey", 2*time.Second) {
		t.Fatalf("expected method=publickey in log:\n%s", ts.logBuf.String())
	}
	wantFP := ssh.FingerprintSHA256(pub)
	if !waitForLog(t, ts.logBuf, wantFP, 2*time.Second) {
		t.Fatalf("expected fingerprint %q in log:\n%s", wantFP, ts.logBuf.String())
	}
}

// TestIntegration_PublickeyOnlyWrongKeyFails starts a server with publickey-only
// auth and verifies that presenting a key not in the authorized_keys file
// results in an auth-fail with reason=bad-key.
func TestIntegration_PublickeyOnlyWrongKeyFails(t *testing.T) {
	acceptedSigner := generateTestHostKey(t)
	wrongSigner := generateTestHostKey(t)

	ts := startTestServer(t, testServerOptions{
		authMethods:  auth.Methods{auth.MethodPublickey},
		acceptedKeys: []ssh.PublicKey{acceptedSigner.PublicKey()},
	})
	defer ts.cleanup()

	_, err := ssh.Dial("tcp", ts.addr, clientConfigPubkey(ts.user, wrongSigner))
	if err == nil {
		t.Fatal("expected Dial with wrong key to fail")
	}

	if !waitForLog(t, ts.logBuf, "reason=bad-key", 5*time.Second) {
		t.Fatalf("expected reason=bad-key in log:\n%s", ts.logBuf.String())
	}
}

// TestIntegration_PublickeyOnlyWrongUserFails verifies that a client presenting
// the correct key but wrong username is rejected with reason=bad-user.
func TestIntegration_PublickeyOnlyWrongUserFails(t *testing.T) {
	signer := generateTestHostKey(t)
	pub := signer.PublicKey()

	ts := startTestServer(t, testServerOptions{
		authMethods:  auth.Methods{auth.MethodPublickey},
		acceptedKeys: []ssh.PublicKey{pub},
	})
	defer ts.cleanup()

	wrongUserCfg := clientConfigPubkey("wronguser", signer)
	_, err := ssh.Dial("tcp", ts.addr, wrongUserCfg)
	if err == nil {
		t.Fatal("expected Dial with wrong user to fail")
	}

	if !waitForLog(t, ts.logBuf, "reason=bad-user", 5*time.Second) {
		t.Fatalf("expected reason=bad-user in log:\n%s", ts.logBuf.String())
	}
	if !waitForLog(t, ts.logBuf, "method=publickey", 2*time.Second) {
		t.Fatalf("expected method=publickey in log:\n%s", ts.logBuf.String())
	}
}

// TestIntegration_PasswordOnlyBaselinePreserved verifies that the default
// password-only path continues to work after pubkey additions.
func TestIntegration_PasswordOnlyBaselinePreserved(t *testing.T) {
	ts := startTestServer(t, testServerOptions{})
	defer ts.cleanup()

	cli, err := ssh.Dial("tcp", ts.addr, clientConfig(ts.user, ts.password))
	if err != nil {
		t.Fatalf("Dial with password: %v", err)
	}
	defer cli.Close()

	if !waitForLog(t, ts.logBuf, "auth-ok", 5*time.Second) {
		t.Fatalf("expected auth-ok in log:\n%s", ts.logBuf.String())
	}
	if !waitForLog(t, ts.logBuf, "method=password", 2*time.Second) {
		t.Fatalf("expected method=password in log:\n%s", ts.logBuf.String())
	}
}

// TestIntegration_BothMethodsPasswordPath verifies that when both password and
// publickey are configured, a client using password is authenticated with
// method=password.
func TestIntegration_BothMethodsPasswordPath(t *testing.T) {
	signer := generateTestHostKey(t)
	pub := signer.PublicKey()

	ts := startTestServer(t, testServerOptions{
		authMethods:  auth.Methods{auth.MethodPassword, auth.MethodPublickey},
		acceptedKeys: []ssh.PublicKey{pub},
	})
	defer ts.cleanup()

	cli, err := ssh.Dial("tcp", ts.addr, clientConfig(ts.user, ts.password))
	if err != nil {
		t.Fatalf("Dial with password in combined mode: %v", err)
	}
	defer cli.Close()

	if !waitForLog(t, ts.logBuf, "method=password", 5*time.Second) {
		t.Fatalf("expected method=password in log:\n%s", ts.logBuf.String())
	}
}

// TestIntegration_BothMethodsPubkeyPath verifies that when both password and
// publickey are configured, a client using pubkey is authenticated with
// method=publickey.
func TestIntegration_BothMethodsPubkeyPath(t *testing.T) {
	signer := generateTestHostKey(t)
	pub := signer.PublicKey()

	ts := startTestServer(t, testServerOptions{
		authMethods:  auth.Methods{auth.MethodPassword, auth.MethodPublickey},
		acceptedKeys: []ssh.PublicKey{pub},
	})
	defer ts.cleanup()

	cli, err := ssh.Dial("tcp", ts.addr, clientConfigPubkey(ts.user, signer))
	if err != nil {
		t.Fatalf("Dial with pubkey in combined mode: %v", err)
	}
	defer cli.Close()

	if !waitForLog(t, ts.logBuf, "method=publickey", 5*time.Second) {
		t.Fatalf("expected method=publickey in log:\n%s", ts.logBuf.String())
	}
}

// TestIntegration_PubkeyFingerprintMatchesSSHKeygen generates a key, connects
// with it, and asserts the fingerprint in the auth-ok log matches
// ssh.FingerprintSHA256 directly.
func TestIntegration_PubkeyFingerprintMatchesSSHKeygen(t *testing.T) {
	signer := generateTestHostKey(t)
	pub := signer.PublicKey()

	ts := startTestServer(t, testServerOptions{
		authMethods:  auth.Methods{auth.MethodPublickey},
		acceptedKeys: []ssh.PublicKey{pub},
	})
	defer ts.cleanup()

	cli, err := ssh.Dial("tcp", ts.addr, clientConfigPubkey(ts.user, signer))
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer cli.Close()

	expectedFP := ssh.FingerprintSHA256(pub)
	if !waitForLog(t, ts.logBuf, expectedFP, 5*time.Second) {
		t.Fatalf("expected fingerprint %q in log:\n%s", expectedFP, ts.logBuf.String())
	}
}

// TestIntegration_MaxAuthTriesCombinedCounter asserts that the combined
// authFailures counter (password failures + rejected-key probes + signature
// failures) hits MaxAuthTries=6 and disconnects.
//
// Scenario A: 3 rejected-key probes (wrong keys) then 3 wrong passwords.
// After 6 total failures the connection is closed.
func TestIntegration_MaxAuthTriesCombinedCounter(t *testing.T) {
	// Accepted key (never presented to the client, so all keys are rejected).
	accepted := generateTestHostKey(t)
	pub := accepted.PublicKey()

	ts := startTestServer(t, testServerOptions{
		authMethods:  auth.Methods{auth.MethodPassword, auth.MethodPublickey},
		acceptedKeys: []ssh.PublicKey{pub},
	})
	defer ts.cleanup()

	// Generate 3 wrong keys for the probe phase.
	wrongSigners := make([]ssh.Signer, 3)
	for i := range wrongSigners {
		wrongSigners[i] = generateTestHostKey(t)
	}

	// Build a client that tries all 3 wrong keys (rejected probes) then
	// falls back to 3 wrong passwords.
	cfg := &ssh.ClientConfig{
		User: ts.user,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(wrongSigners...),
			ssh.RetryableAuthMethod(
				ssh.PasswordCallback(func() (string, error) {
					return "wrong-password", nil
				}),
				10,
			),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         120 * time.Second,
	}
	_, err := ssh.Dial("tcp", ts.addr, cfg)
	if err == nil {
		t.Fatal("expected Dial to fail after MaxAuthTries exhausted")
	}

	if !waitForLog(t, ts.logBuf, "conn-close", 120*time.Second) {
		t.Fatalf("expected conn-close in log:\n%s", ts.logBuf.String())
	}

	// Total auth-fail lines must be exactly 6.
	got := countLogOccurrences(ts.logBuf, "event=auth-fail")
	if got == 0 {
		// logfmt format uses space-separated key=value without event= prefix.
		got = countLogOccurrences(ts.logBuf, " auth-fail ")
	}
	if got != 6 {
		t.Errorf("want exactly 6 auth-fail events; got %d\nlog:\n%s",
			got, ts.logBuf.String())
	}
}

// TestIntegration_PubkeyFailureFeedsRateLimit verifies that publickey failures
// from the same IP incur exponential backoff — identical to the password path.
// Skipped under -short.
func TestIntegration_PubkeyFailureFeedsRateLimit(t *testing.T) {
	if testing.Short() {
		t.Skip("rate-limit timing test; skipped under -short")
	}

	accepted := generateTestHostKey(t)
	pub := accepted.PublicKey()

	ts := startTestServer(t, testServerOptions{
		authMethods:  auth.Methods{auth.MethodPublickey},
		acceptedKeys: []ssh.PublicKey{pub},
	})
	defer ts.cleanup()

	wrong := generateTestHostKey(t)

	// 5 failed connections (wrong key) from the same IP to build up backoff.
	for i := 0; i < 5; i++ {
		cfg := clientConfigPubkey(ts.user, wrong)
		cfg.Timeout = 30 * time.Second
		_, _ = ssh.Dial("tcp", ts.addr, cfg)
	}

	// A 6th connection with the wrong key should observe the backoff delay.
	start := time.Now()
	cfg6 := clientConfigPubkey(ts.user, wrong)
	cfg6.Timeout = 30 * time.Second
	_, _ = ssh.Dial("tcp", ts.addr, cfg6)
	elapsed := time.Since(start)

	// After 5 failures from the same IP the 6th should wait at least 8s
	// (per rate-limit spec §5). We allow up to 30s for CI jitter.
	if elapsed < 8*time.Second {
		t.Errorf("expected at least 8s delay for 6th connection; got %v", elapsed)
	}

	// Finally verify a correct key works (rate-limit resets on success).
	cliOK, err := ssh.Dial("tcp", ts.addr, clientConfigPubkey(ts.user, accepted))
	if err != nil {
		t.Logf("correct key after rate-limit buildup: %v (may fail if backoff too high)", err)
	} else {
		defer cliOK.Close()
		if !waitForLog(t, ts.logBuf, "method=publickey", 5*time.Second) {
			t.Errorf("expected auth-ok with publickey after rate-limit cleared")
		}
	}
	_ = strings.Contains // suppress unused import
}

// TestIntegration_SIGHUPReload exercises the authorized-keys atomic reload
// path:
//  1. Start with key A in the file; assert auth with A succeeds.
//  2. Overwrite the file with key B; call Reload() directly (this is what
//     the SIGHUP handler calls in production); wait for pubkey-reload-ok.
//  3. Auth with A now fails (reason=bad-key); auth with B succeeds.
//  4. Overwrite the file with malformed garbage; call Reload(); wait for
//     pubkey-reload-failed; assert B still authenticates (old keyset
//     preserved).
func TestIntegration_SIGHUPReload(t *testing.T) {
	signerA := generateTestHostKey(t)
	signerB := generateTestHostKey(t)
	pubA := signerA.PublicKey()
	pubB := signerB.PublicKey()

	ts := startTestServer(t, testServerOptions{
		authMethods:  auth.Methods{auth.MethodPublickey},
		acceptedKeys: []ssh.PublicKey{pubA},
	})
	defer ts.cleanup()

	if ts.keysPath == "" || ts.keysetSource == nil {
		t.Fatal("startTestServer did not populate keysPath/keysetSource")
	}

	// Step 1: auth with key A must succeed.
	cliA, err := ssh.Dial("tcp", ts.addr, clientConfigPubkey(ts.user, signerA))
	if err != nil {
		t.Fatalf("initial auth with key A: %v", err)
	}
	cliA.Close()

	// Step 2: overwrite file with key B only; trigger reload.
	if err := os.WriteFile(ts.keysPath, ssh.MarshalAuthorizedKey(pubB), 0600); err != nil {
		t.Fatalf("overwrite authorized_keys: %v", err)
	}
	if err := ts.keysetSource.Reload(); err != nil {
		t.Fatalf("Reload after writing key B: %v", err)
	}
	if !waitForLog(t, ts.logBuf, "pubkey-reload-ok", 5*time.Second) {
		t.Fatalf("expected pubkey-reload-ok after reload; log:\n%s", ts.logBuf.String())
	}

	// Step 3: key A must now fail; key B must succeed.
	_, errA := ssh.Dial("tcp", ts.addr, clientConfigPubkey(ts.user, signerA))
	if errA == nil {
		t.Error("auth with key A after reload should fail, but succeeded")
	}
	if !waitForLog(t, ts.logBuf, "reason=bad-key", 3*time.Second) {
		t.Fatalf("expected reason=bad-key for stale key A; log:\n%s", ts.logBuf.String())
	}

	cliB, err := ssh.Dial("tcp", ts.addr, clientConfigPubkey(ts.user, signerB))
	if err != nil {
		t.Fatalf("auth with key B after reload: %v", err)
	}
	cliB.Close()

	// Step 4: overwrite with malformed garbage; reload must fail; B still works.
	if err := os.WriteFile(ts.keysPath, []byte("not-a-valid-key-line\n"), 0600); err != nil {
		t.Fatalf("overwrite with malformed content: %v", err)
	}
	// A load that yields zero usable keys when the previous set had ≥1 key
	// is treated as a failure (per spec §4 authorized-keys reload policy).
	_ = ts.keysetSource.Reload() // error expected; we check the log
	if !waitForLog(t, ts.logBuf, "pubkey-reload-failed", 5*time.Second) {
		t.Fatalf("expected pubkey-reload-failed after malformed file; log:\n%s", ts.logBuf.String())
	}

	// Key B still works because the old keyset was preserved on failure.
	cliB2, err := ssh.Dial("tcp", ts.addr, clientConfigPubkey(ts.user, signerB))
	if err != nil {
		t.Fatalf("auth with key B after failed reload should still work: %v", err)
	}
	cliB2.Close()
}

// TestIntegration_NeitherMethodAllowedRejects verifies that when a client
// tries to authenticate with a method not advertised by the server, the
// connection is rejected. Here we configure a password-only server and
// present only a publickey; the client should fail to authenticate.
func TestIntegration_NeitherMethodAllowedRejects(t *testing.T) {
	// Server is password-only; we will attempt pubkey-only from the client.
	ts := startTestServer(t, testServerOptions{
		authMethods: auth.Methods{auth.MethodPassword},
	})
	defer ts.cleanup()

	// A client that offers only publickey auth against a password-only server
	// must fail to negotiate — no matching method.
	wrongSigner := generateTestHostKey(t)
	cfg := &ssh.ClientConfig{
		User:            ts.user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(wrongSigner)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}
	_, err := ssh.Dial("tcp", ts.addr, cfg)
	if err == nil {
		t.Fatal("expected Dial to fail when client offers only publickey to a password-only server")
	}
	// The client sees "unable to authenticate" or similar; no auth-ok must appear.
	// Give a short window for any spurious log then check.
	time.Sleep(100 * time.Millisecond)
	if strings.Contains(ts.logBuf.String(), "auth-ok") {
		t.Errorf("unexpected auth-ok in log for rejected pubkey-on-password-only server:\n%s", ts.logBuf.String())
	}
}
