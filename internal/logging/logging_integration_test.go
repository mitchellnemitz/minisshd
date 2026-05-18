package logging_test

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/mitchellnemitz/minissh/internal/logging"
)

// Integration-level assertions on the structured logger. The unit tests
// in internal/logging/*_test.go already cover the field-by-field scrub;
// here we assert (a) the scrub still works when the password is fed
// through real event methods at higher volume, and (b) auth failures
// emitted by the server carry the correct reason field.

// TestIntegration_PasswordNeverAppearsInStructuredEvents fires the
// password value through every event method and asserts the output
// contains [REDACTED] in its place — never the literal value.
func TestIntegration_PasswordNeverAppearsInStructuredEvents(t *testing.T) {
	const password = "hunter2-secret"
	var buf bytes.Buffer
	l := logging.New(&buf, password)

	// Drive each method with the password baked into at least one field.
	l.Listening(password, 2222, "SHA256:"+password, password, 1234)
	l.ConnOpen(password)
	l.ConnClose(password, 5*time.Second)
	l.AuthOK(password, password)
	l.AuthFail(password, password, "bad-user", 3, 4*time.Second)
	l.Session(password, password)
	l.Reject(password, password)
	l.ShutdownSignal(99, password, password)
	l.DrainTimeout(password, password, 17)
	l.Error("oops "+password, password)

	out := buf.String()
	if strings.Contains(out, password) {
		t.Fatalf("password leaked into log output:\n%s", out)
	}
	if !strings.Contains(out, "[REDACTED]") {
		t.Fatalf("expected [REDACTED] sentinel in output:\n%s", out)
	}
}

// TestIntegration_AuthFailCarriesCorrectReason drives the server with
// one wrong-user and one wrong-password attempt and asserts the captured
// log contains exactly one of each reason.
func TestIntegration_AuthFailCarriesCorrectReason(t *testing.T) {
	ts := startTestServer(t, testServerOptions{})
	defer ts.cleanup()

	// Wrong user.
	_, err := ssh.Dial("tcp", ts.addr, clientConfig("nobody", ts.password))
	if err == nil {
		t.Fatalf("expected wrong-user Dial to fail")
	}

	if !waitForLog(t, ts.logBuf, "reason=bad-user", 5*time.Second) {
		t.Fatalf("expected reason=bad-user in log:\n%s", ts.logBuf.String())
	}

	// Wrong password.
	_, err = ssh.Dial("tcp", ts.addr, clientConfig(ts.user, "definitely-wrong"))
	if err == nil {
		t.Fatalf("expected wrong-password Dial to fail")
	}

	if !waitForLog(t, ts.logBuf, "reason=bad-password", 5*time.Second) {
		t.Fatalf("expected reason=bad-password in log:\n%s", ts.logBuf.String())
	}

	// Quick sanity: we got exactly the events we expected, not extras.
	if got := countLogOccurrences(ts.logBuf, "reason=bad-user"); got != 1 {
		t.Errorf("expected 1 bad-user event; got %d", got)
	}
	if got := countLogOccurrences(ts.logBuf, "reason=bad-password"); got != 1 {
		t.Errorf("expected 1 bad-password event; got %d", got)
	}
}
