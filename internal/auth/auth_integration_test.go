package auth_test

import (
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// Integration tests for the auth path drive the in-process server via
// golang.org/x/crypto/ssh as the client. Scenarios from spec §13.3.

// TestIntegration_CorrectCredentialsAllowShell is a smoke test that the
// auth callback accepts the configured credentials and the session opens.
func TestIntegration_CorrectCredentialsAllowShell(t *testing.T) {
	ts := startTestServer(t, testServerOptions{})
	defer ts.cleanup()

	cli, err := ssh.Dial("tcp", ts.addr, clientConfig(ts.user, ts.password))
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer cli.Close()

	sess, err := cli.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	_ = sess.Close()

	if !waitForLog(t, ts.logBuf, "auth-ok", 2*time.Second) {
		t.Fatalf("expected auth-ok in log:\n%s", ts.logBuf.String())
	}
}

func TestIntegration_WrongUserLogsBadUser(t *testing.T) {
	ts := startTestServer(t, testServerOptions{})
	defer ts.cleanup()

	cfg := clientConfig("wronguser", ts.password)
	_, err := ssh.Dial("tcp", ts.addr, cfg)
	if err == nil {
		t.Fatalf("expected Dial to fail with wrong user")
	}

	if !waitForLog(t, ts.logBuf, "reason=bad-user", 3*time.Second) {
		t.Fatalf("expected `reason=bad-user` in log:\n%s", ts.logBuf.String())
	}
}

func TestIntegration_WrongPasswordLogsBadPassword(t *testing.T) {
	ts := startTestServer(t, testServerOptions{})
	defer ts.cleanup()

	cfg := clientConfig(ts.user, "wrong-password")
	_, err := ssh.Dial("tcp", ts.addr, cfg)
	if err == nil {
		t.Fatalf("expected Dial to fail with wrong password")
	}

	if !waitForLog(t, ts.logBuf, "reason=bad-password", 5*time.Second) {
		t.Fatalf("expected `reason=bad-password` in log:\n%s", ts.logBuf.String())
	}
}

// TestIntegration_SixWrongPasswordsCloseConnection proves the server enforces
// a server-side password-attempt cap regardless of how many the client offers.
// We give the client 10 wrong-password attempts via ssh.RetryableAuthMethod
// and expect the connection to be closed after exactly 6 failed attempts.
//
// Spec §4: MaxAuthTries = 6 (combined counter for password failures, publickey
// signature failures, and rejected-key queries). golang.org/x/crypto/ssh
// v0.51.0 exempts only the initial `none` probe from the counter, so
// MaxAuthTries=6 delivers six real password attempts before disconnect.
// See also TestIntegration_MaxAuthTriesCombinedCounter for the combined-counter
// assertion (publickey probes + password failures sharing a single counter).
func TestIntegration_SixWrongPasswordsCloseConnection(t *testing.T) {
	ts := startTestServer(t, testServerOptions{})
	defer ts.cleanup()

	cfg := &ssh.ClientConfig{
		User: ts.user,
		Auth: []ssh.AuthMethod{
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
		t.Fatalf("expected Dial to fail")
	}

	if !waitForLog(t, ts.logBuf, "conn-close", 120*time.Second) {
		t.Fatalf("expected conn-close in log:\n%s", ts.logBuf.String())
	}

	got := countLogOccurrences(ts.logBuf, "reason=bad-password")
	if got != 6 {
		t.Fatalf("want exactly 6 bad-password events; got %d; log:\n%s", got, ts.logBuf.String())
	}
	// Sanity: client's error mentions auth.
	if err != nil && !strings.Contains(strings.ToLower(err.Error()), "auth") &&
		!strings.Contains(strings.ToLower(err.Error()), "permission") &&
		!strings.Contains(strings.ToLower(err.Error()), "unable") {
		t.Logf("client error (informational): %v", err)
	}
}
