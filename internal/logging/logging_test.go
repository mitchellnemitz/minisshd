package logging

import (
	"bytes"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// eventLineRE matches the spec §13.2 envelope:
//
//	^\S+ (INFO|WARN|ERROR) +\S+ .*$
var eventLineRE = regexp.MustCompile(`^\S+ (INFO|WARN|ERROR) +\S+ .*$`)

// newTestLogger returns a Logger whose buffer the caller can inspect. The
// clock is frozen for stable test output.
func newTestLogger(password string) (*Logger, *bytes.Buffer) {
	buf := &bytes.Buffer{}
	l := New(buf, password)
	l.now = func() time.Time {
		return time.Date(2026, 5, 17, 14, 22, 1, 0, time.UTC)
	}
	return l, buf
}

// lastLine returns the most recent emitted line (without trailing newline).
func lastLine(t *testing.T, buf *bytes.Buffer) string {
	t.Helper()
	out := buf.String()
	if !strings.HasSuffix(out, "\n") {
		t.Fatalf("output did not end with newline: %q", out)
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	return lines[len(lines)-1]
}

// TestEvelopes asserts every event method produces a line that matches the
// spec §13.2 regex and contains the documented field names.
func TestEnvelopes(t *testing.T) {
	cases := []struct {
		name     string
		fields   []string // required field names (must appear as `name=`)
		emit     func(l *Logger)
		wantName string
	}{
		{
			name:     "listening",
			wantName: "listening",
			fields:   []string{"bind=", "port=", "fingerprint=", "user=", "pid="},
			emit: func(l *Logger) {
				l.Listening("0.0.0.0", 2222, "SHA256:abc", "alice", 4711)
			},
		},
		{
			name:     "conn-open",
			wantName: "conn-open",
			fields:   []string{"remote="},
			emit: func(l *Logger) {
				l.ConnOpen("192.168.1.42:51223")
			},
		},
		{
			name:     "conn-close",
			wantName: "conn-close",
			fields:   []string{"remote=", "duration="},
			emit: func(l *Logger) {
				l.ConnClose("192.168.1.42:51223", 27*time.Second)
			},
		},
		{
			name:     "auth-ok",
			wantName: "auth-ok",
			fields:   []string{"remote=", "user="},
			emit: func(l *Logger) {
				l.AuthOK("192.168.1.42:51223", "alice")
			},
		},
		{
			name:     "auth-fail",
			wantName: "auth-fail",
			fields:   []string{"remote=", "user=", "reason=", "attempt=", "next_delay="},
			emit: func(l *Logger) {
				l.AuthFail("10.0.0.5:55001", "bob", "bad-user", 1, time.Second)
			},
		},
		{
			name:     "session",
			wantName: "session",
			fields:   []string{"remote=", "kind="},
			emit: func(l *Logger) {
				l.Session("192.168.1.42:51223", "shell")
			},
		},
		{
			name:     "reject",
			wantName: "reject",
			fields:   []string{"remote=", "what="},
			emit: func(l *Logger) {
				l.Reject("192.168.1.42:51223", "tcpip")
			},
		},
		{
			name:     "shutdown-signal",
			wantName: "shutdown-signal",
			fields:   []string{"pgid=", "sig=", "reason="},
			emit: func(l *Logger) {
				l.ShutdownSignal(4733, "HUP", "channel-close")
			},
		},
		{
			name:     "drain-timeout",
			wantName: "drain-timeout",
			fields:   []string{"remote=", "kind=", "bytes_dropped="},
			emit: func(l *Logger) {
				l.DrainTimeout("192.168.1.42:51223", "shell", 1024)
			},
		},
		{
			name:     "error-with-remote",
			wantName: "error",
			fields:   []string{"message=", "remote="},
			emit: func(l *Logger) {
				l.Error("boom", "192.168.1.42:51223")
			},
		},
		{
			name:     "error-without-remote",
			wantName: "error",
			fields:   []string{"message="},
			emit: func(l *Logger) {
				l.Error("boom", "")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l, buf := newTestLogger("")
			tc.emit(l)
			line := lastLine(t, buf)
			if !eventLineRE.MatchString(line) {
				t.Fatalf("line does not match envelope regex: %q", line)
			}
			tokens := strings.SplitN(line, " ", 3)
			if len(tokens) < 3 {
				t.Fatalf("expected at least 3 tokens, got %d: %q", len(tokens), line)
			}
			// Token 2 (index 2) starts with the event name.
			rest := tokens[2]
			if !strings.HasPrefix(rest, tc.wantName+" ") && rest != tc.wantName {
				t.Errorf("event name mismatch: got prefix %q, want %q", rest, tc.wantName)
			}
			for _, f := range tc.fields {
				if !strings.Contains(line, f) {
					t.Errorf("missing field %q in %q", f, line)
				}
			}
		})
	}
}

// TestErrorOmitsEmptyRemote asserts that the `remote` field is dropped
// entirely when Error is called with an empty remote.
func TestErrorOmitsEmptyRemote(t *testing.T) {
	l, buf := newTestLogger("")
	l.Error("disk full", "")
	out := buf.String()
	if strings.Contains(out, "remote=") {
		t.Errorf("expected no remote field, got %q", out)
	}
	if !strings.Contains(out, "message=") {
		t.Errorf("expected message field, got %q", out)
	}
}

// TestQuotingRules covers the §9 value-quoting rules.
func TestQuotingRules(t *testing.T) {
	cases := []struct {
		name      string
		value     string
		wantField string // exactly what we expect in the emitted line, e.g. `user="with space"`
	}{
		{name: "plain", value: "plain", wantField: "user=plain"},
		{name: "with-space", value: "with space", wantField: `user="with space"`},
		{name: "with-tab", value: "a\tb", wantField: "user=\"a\tb\""},
		{name: "with-quote", value: `with "quote"`, wantField: `user="with \"quote\""`},
		// Backslash on its own does NOT trigger quoting (§9: quote on whitespace,
		// `=`, `"`, or empty). Inside an already-quoted value it must be
		// escaped, so combine with a space to force quoting.
		{name: "backslash-bare", value: `a\b`, wantField: `user=a\b`},
		{name: "backslash-in-quoted", value: `a\b c`, wantField: `user="a\\b c"`},
		{name: "empty", value: "", wantField: `user=""`},
		{name: "with-equals", value: "a=b", wantField: `user="a=b"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l, buf := newTestLogger("")
			l.AuthOK("1.2.3.4:5", tc.value)
			line := lastLine(t, buf)
			if !strings.Contains(line, tc.wantField) {
				t.Errorf("missing %q in %q", tc.wantField, line)
			}
		})
	}
}

// TestIPLiteralsUnquoted asserts IPv4 and IPv6 literals appear unquoted —
// none of their characters trigger §9 quoting.
func TestIPLiteralsUnquoted(t *testing.T) {
	cases := []string{
		"192.168.1.42:51223",
		"[2001:db8::1]:51223",
		"::1",
		"::",
	}
	for _, addr := range cases {
		t.Run(addr, func(t *testing.T) {
			l, buf := newTestLogger("")
			l.ConnOpen(addr)
			line := lastLine(t, buf)
			want := "remote=" + addr
			if !strings.Contains(line, want) {
				t.Errorf("expected unquoted %q in %q", want, line)
			}
			// Also verify there is no quoted form for this address.
			quoted := `remote="` + addr + `"`
			if strings.Contains(line, quoted) {
				t.Errorf("unexpectedly quoted IP literal in %q", line)
			}
		})
	}
}

// TestPasswordScrubGuard injects the configured password as the value of
// every string field across every event and asserts the literal password
// never appears in the captured output.
func TestPasswordScrubGuard(t *testing.T) {
	const pw = "hunter2"
	l, buf := newTestLogger(pw)

	// Push the password through every string-valued slot we can reach.
	l.Listening(pw, 2222, pw, pw, 1)
	l.ConnOpen(pw)
	l.ConnClose(pw, time.Second)
	l.AuthOK(pw, pw)
	l.AuthFail(pw, pw, pw, 1, time.Second)
	l.Session(pw, pw)
	l.Reject(pw, pw)
	l.ShutdownSignal(1, pw, pw)
	l.DrainTimeout(pw, pw, 0)
	l.Error(pw, pw)

	out := buf.String()
	if strings.Contains(out, pw) {
		t.Fatalf("password leaked into output:\n%s", out)
	}
	if !strings.Contains(out, redacted) {
		t.Errorf("expected %q replacement in output:\n%s", redacted, out)
	}
}

// TestPasswordScrubDisabledWhenEmpty proves the scrub is gated on a non-empty
// configured password — when the configured password is "", values equal to
// "hunter2" must pass through verbatim.
func TestPasswordScrubDisabledWhenEmpty(t *testing.T) {
	l, buf := newTestLogger("")
	l.AuthOK("1.2.3.4:5", "hunter2")
	out := buf.String()
	if !strings.Contains(out, "user=hunter2") {
		t.Errorf("expected literal user=hunter2 in %q", out)
	}
	if strings.Contains(out, redacted) {
		t.Errorf("unexpected redaction with empty configured password: %q", out)
	}
}

// TestConcurrentEmission runs 50 goroutines emitting events in parallel; the
// test asserts every line is well-formed (no interleaving) and matches the
// envelope regex. Combined with `go test -race`, this exercises the mutex.
func TestConcurrentEmission(t *testing.T) {
	const goroutines = 50
	const perGoroutine = 20

	buf := &bytes.Buffer{}
	l := New(buf, "")
	// Real clock here — the test only checks line shape, not timestamps.

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < perGoroutine; j++ {
				l.ConnOpen("192.168.1.42:51223")
				l.AuthFail("10.0.0.5:55001", "bob", "bad-user", id, 2*time.Second)
				l.Reject("[2001:db8::1]:51223", "x11")
			}
		}(i)
	}
	wg.Wait()

	out := buf.String()
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	wantLines := goroutines * perGoroutine * 3
	if len(lines) != wantLines {
		t.Fatalf("got %d lines, want %d", len(lines), wantLines)
	}
	for i, line := range lines {
		if !eventLineRE.MatchString(line) {
			t.Fatalf("line %d malformed (possible interleave): %q", i, line)
		}
	}
}

// TestEnvelopeShape locks down the exact opening of the emitted line so that
// downstream regex-based assertions in integration tests remain stable.
func TestEnvelopeShape(t *testing.T) {
	l, buf := newTestLogger("")
	l.Listening("0.0.0.0", 2222, "SHA256:abc", "alice", 4711)
	line := lastLine(t, buf)
	const wantPrefix = "2026-05-17T14:22:01Z INFO listening "
	if !strings.HasPrefix(line, wantPrefix) {
		t.Errorf("prefix mismatch:\ngot  %q\nwant prefix %q", line, wantPrefix)
	}
}
