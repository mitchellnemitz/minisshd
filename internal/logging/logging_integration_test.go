package logging_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/mitchellnemitz/minisshd/internal/logging"
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
	l := logging.New(&buf, password, logging.FormatLogfmt)

	// Drive each method with the password baked into at least one field.
	l.Listening(password, 2222, "SHA256:"+password, password, 1234, "password", 0)
	l.ConnOpen(password)
	l.ConnClose(password, 5*time.Second)
	l.AuthOK(password, password, "password", "")
	l.AuthFail(password, password, "password", "bad-user", 3, 4*time.Second, "")
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

// TestIntegration_JSONLogCapture starts the server in JSON mode, drives one
// good auth and one bad auth, then parses the captured lines as JSON and
// asserts the expected event sequence.
func TestIntegration_JSONLogCapture(t *testing.T) {
	ts := startTestServer(t, testServerOptions{
		logFormat: logging.FormatJSON,
	})
	defer ts.cleanup()

	// Good auth attempt.
	client, err := ssh.Dial("tcp", ts.addr, clientConfig(ts.user, ts.password))
	if err != nil {
		t.Fatalf("good auth failed: %v", err)
	}
	client.Close()

	if !waitForLog(t, ts.logBuf, `"event":"conn-close"`, 5*time.Second) {
		t.Fatalf("conn-close event not seen; log:\n%s", ts.logBuf.String())
	}

	// Bad auth attempt (wrong password).
	_, err = ssh.Dial("tcp", ts.addr, clientConfig(ts.user, "wrong"))
	if err == nil {
		t.Fatalf("expected bad-auth Dial to fail")
	}

	if !waitForLog(t, ts.logBuf, `"event":"auth-fail"`, 5*time.Second) {
		t.Fatalf("auth-fail event not seen; log:\n%s", ts.logBuf.String())
	}

	// Parse all captured lines as JSON and assert event structure.
	out := ts.logBuf.String()
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")

	var events []map[string]any
	for i, line := range lines {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Errorf("line %d is not valid JSON: %q — %v", i, line, err)
			continue
		}
		events = append(events, m)
	}

	countEvent := func(name string) int {
		n := 0
		for _, e := range events {
			if e["event"] == name {
				n++
			}
		}
		return n
	}

	// Note: the test harness (startTestServer) does not call logger.Listening;
	// that event is emitted only by cmd/minisshd/main.go. We assert on the
	// events actually emitted by the server accept loop.
	if countEvent("conn-open") < 1 {
		t.Error("expected at least one conn-open event")
	}
	if countEvent("auth-ok") < 1 {
		t.Error("expected at least one auth-ok event")
	}
	if countEvent("conn-close") < 1 {
		t.Error("expected at least one conn-close event")
	}
	if countEvent("auth-fail") < 1 {
		t.Error("expected at least one auth-fail event")
	}

	// Verify auth-fail has the correct field types.
	for _, e := range events {
		if e["event"] != "auth-fail" {
			continue
		}
		if _, ok := e["attempt"].(float64); !ok {
			t.Errorf("auth-fail.attempt should be float64 (JSON number), got %T", e["attempt"])
		}
		if _, ok := e["next_delay"].(float64); !ok {
			t.Errorf("auth-fail.next_delay should be float64 (JSON number), got %T", e["next_delay"])
		}
	}
}

// TestIntegration_JSONPasswordScrub_QuoteInPassword starts the server with a
// password containing a double-quote and asserts the password never leaks in
// JSON output, even in its JSON-encoded form.
func TestIntegration_JSONPasswordScrub_QuoteInPassword(t *testing.T) {
	const pw = `"hello"world`
	ts := startTestServer(t, testServerOptions{
		password:  pw,
		logFormat: logging.FormatJSON,
	})
	defer ts.cleanup()

	// Drive a failed auth attempt.
	_, err := ssh.Dial("tcp", ts.addr, clientConfig(ts.user, "wrong"))
	if err == nil {
		t.Fatalf("expected bad-auth Dial to fail")
	}

	if !waitForLog(t, ts.logBuf, `"event":"auth-fail"`, 5*time.Second) {
		t.Fatalf("auth-fail event not seen; log:\n%s", ts.logBuf.String())
	}

	out := ts.logBuf.String()
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	for i, line := range lines {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Errorf("line %d not valid JSON after scrub: %q — %v", i, line, err)
		}
	}

	// Raw password must not appear.
	if strings.Contains(out, pw) {
		t.Errorf("raw password leaked in JSON output:\n%s", out)
	}
	// Encoded form must not appear.
	const encodedInner = `\"hello\"world`
	if strings.Contains(out, encodedInner) {
		t.Errorf("JSON-encoded password leaked in output:\n%s", out)
	}
}
