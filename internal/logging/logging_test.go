package logging

import (
	"bytes"
	"encoding/json"
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
// clock is frozen for stable test output. The format defaults to FormatLogfmt.
func newTestLogger(password string) (*Logger, *bytes.Buffer) {
	return newTestLoggerFmt(password, FormatLogfmt)
}

// newTestLoggerFmt returns a Logger with the specified format.
func newTestLoggerFmt(password string, format Format) (*Logger, *bytes.Buffer) {
	buf := &bytes.Buffer{}
	l := New(buf, password, format)
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
			fields:   []string{"bind=", "port=", "fingerprint=", "user=", "pid=", "auth_methods=", "pubkey_count="},
			emit: func(l *Logger) {
				l.Listening("0.0.0.0", 2222, "SHA256:abc", "alice", 4711, "password", 0)
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
			fields:   []string{"remote=", "user=", "method="},
			emit: func(l *Logger) {
				l.AuthOK("192.168.1.42:51223", "alice", "password", "")
			},
		},
		{
			name:     "auth-fail",
			wantName: "auth-fail",
			fields:   []string{"remote=", "user=", "method=", "reason=", "attempt=", "next_delay="},
			emit: func(l *Logger) {
				l.AuthFail("10.0.0.5:55001", "bob", "password", "bad-user", 1, time.Second, "")
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

// TestEnvelopes_JSON is the JSON twin of TestEnvelopes. For each event it
// asserts the emitted line parses as JSON with the expected fields and types.
func TestEnvelopes_JSON(t *testing.T) {
	cases := []struct {
		name        string
		wantEvent   string
		wantKeys    []string // all must appear in the parsed object
		wantIntKeys []string // these must have float64 type (JSON numbers)
		wantDurKeys []string // duration keys — must be float64 in JSON
		emit        func(l *Logger)
	}{
		{
			name:        "listening",
			wantEvent:   "listening",
			wantKeys:    []string{"ts", "level", "event", "bind", "port", "fingerprint", "user", "pid", "auth_methods", "pubkey_count"},
			wantIntKeys: []string{"port", "pid", "pubkey_count"},
			emit: func(l *Logger) {
				l.Listening("0.0.0.0", 2222, "SHA256:abc", "alice", 4711, "password", 0)
			},
		},
		{
			name:      "conn-open",
			wantEvent: "conn-open",
			wantKeys:  []string{"ts", "level", "event", "remote"},
			emit: func(l *Logger) {
				l.ConnOpen("192.168.1.42:51223")
			},
		},
		{
			name:        "conn-close",
			wantEvent:   "conn-close",
			wantKeys:    []string{"ts", "level", "event", "remote", "duration"},
			wantDurKeys: []string{"duration"},
			emit: func(l *Logger) {
				l.ConnClose("192.168.1.42:51223", 27*time.Second)
			},
		},
		{
			name:      "auth-ok",
			wantEvent: "auth-ok",
			wantKeys:  []string{"ts", "level", "event", "remote", "user", "method"},
			emit: func(l *Logger) {
				l.AuthOK("192.168.1.42:51223", "alice", "password", "")
			},
		},
		{
			name:        "auth-fail",
			wantEvent:   "auth-fail",
			wantKeys:    []string{"ts", "level", "event", "remote", "user", "method", "reason", "attempt", "next_delay"},
			wantIntKeys: []string{"attempt"},
			wantDurKeys: []string{"next_delay"},
			emit: func(l *Logger) {
				l.AuthFail("10.0.0.5:55001", "bob", "password", "bad-user", 1, time.Second, "")
			},
		},
		{
			name:      "session",
			wantEvent: "session",
			wantKeys:  []string{"ts", "level", "event", "remote", "kind"},
			emit: func(l *Logger) {
				l.Session("192.168.1.42:51223", "shell")
			},
		},
		{
			name:      "reject",
			wantEvent: "reject",
			wantKeys:  []string{"ts", "level", "event", "remote", "what"},
			emit: func(l *Logger) {
				l.Reject("192.168.1.42:51223", "tcpip")
			},
		},
		{
			name:        "shutdown-signal",
			wantEvent:   "shutdown-signal",
			wantKeys:    []string{"ts", "level", "event", "pgid", "sig", "reason"},
			wantIntKeys: []string{"pgid"},
			emit: func(l *Logger) {
				l.ShutdownSignal(4733, "HUP", "channel-close")
			},
		},
		{
			name:        "drain-timeout",
			wantEvent:   "drain-timeout",
			wantKeys:    []string{"ts", "level", "event", "remote", "kind", "bytes_dropped"},
			wantIntKeys: []string{"bytes_dropped"},
			emit: func(l *Logger) {
				l.DrainTimeout("192.168.1.42:51223", "shell", 1024)
			},
		},
		{
			name:      "error-with-remote",
			wantEvent: "error",
			wantKeys:  []string{"ts", "level", "event", "message", "remote"},
			emit: func(l *Logger) {
				l.Error("boom", "192.168.1.42:51223")
			},
		},
		{
			name:      "error-without-remote",
			wantEvent: "error",
			wantKeys:  []string{"ts", "level", "event", "message"},
			emit: func(l *Logger) {
				l.Error("boom", "")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l, buf := newTestLoggerFmt("", FormatJSON)
			tc.emit(l)
			line := lastLine(t, buf)

			var m map[string]any
			if err := json.Unmarshal([]byte(line), &m); err != nil {
				t.Fatalf("json.Unmarshal failed: %v\nline: %q", err, line)
			}

			// Check all expected keys are present.
			for _, k := range tc.wantKeys {
				if _, ok := m[k]; !ok {
					t.Errorf("missing key %q in JSON: %s", k, line)
				}
			}

			// Check event name.
			if got, _ := m["event"].(string); got != tc.wantEvent {
				t.Errorf("event=%q want %q", got, tc.wantEvent)
			}

			// Check integer keys have float64 type (JSON number).
			for _, k := range tc.wantIntKeys {
				v, ok := m[k]
				if !ok {
					continue
				}
				if _, ok := v.(float64); !ok {
					t.Errorf("key %q: want float64 (JSON number), got %T", k, v)
				}
			}

			// Check duration keys have float64 type.
			for _, k := range tc.wantDurKeys {
				v, ok := m[k]
				if !ok {
					continue
				}
				if _, ok := v.(float64); !ok {
					t.Errorf("duration key %q: want float64 (JSON number), got %T", k, v)
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
			l.AuthOK("1.2.3.4:5", tc.value, "password", "")
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
	l.Listening(pw, 2222, pw, pw, 1, pw, 0)
	l.ConnOpen(pw)
	l.ConnClose(pw, time.Second)
	l.AuthOK(pw, pw, pw, pw)
	l.AuthFail(pw, pw, pw, pw, 1, time.Second, pw)
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
	l.AuthOK("1.2.3.4:5", "hunter2", "password", "")
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
	l := New(buf, "", FormatLogfmt)
	// Real clock here — the test only checks line shape, not timestamps.

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < perGoroutine; j++ {
				l.ConnOpen("192.168.1.42:51223")
				l.AuthFail("10.0.0.5:55001", "bob", "password", "bad-user", id, 2*time.Second, "")
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
	l.Listening("0.0.0.0", 2222, "SHA256:abc", "alice", 4711, "password", 0)
	line := lastLine(t, buf)
	const wantPrefix = "2026-05-17T14:22:01Z INFO listening "
	if !strings.HasPrefix(line, wantPrefix) {
		t.Errorf("prefix mismatch:\ngot  %q\nwant prefix %q", line, wantPrefix)
	}
}

// ---- JSON-specific tests ----

// TestJSONEnvelope_FieldOrder asserts that the JSON output begins with
// {"ts":... and that ts, level, event come first in that order.
func TestJSONEnvelope_FieldOrder(t *testing.T) {
	l, buf := newTestLoggerFmt("", FormatJSON)
	l.Listening("0.0.0.0", 2222, "SHA256:abc", "alice", 4711, "password", 0)
	line := lastLine(t, buf)
	if !strings.HasPrefix(line, `{"ts":`) {
		t.Errorf("JSON line should begin with {\"ts\":, got: %q", line)
	}
	// Verify level comes before event in the raw string.
	levelIdx := strings.Index(line, `"level":`)
	eventIdx := strings.Index(line, `"event":`)
	if levelIdx < 0 || eventIdx < 0 || levelIdx >= eventIdx {
		t.Errorf("expected \"level\" before \"event\" in: %q", line)
	}
	// After the envelope, event-specific fields should be alphabetical.
	// For listening: bind, fingerprint, pid, port, user
	bindIdx := strings.Index(line, `"bind":`)
	fpIdx := strings.Index(line, `"fingerprint":`)
	pidIdx := strings.Index(line, `"pid":`)
	portIdx := strings.Index(line, `"port":`)
	userIdx := strings.Index(line, `"user":`)
	if bindIdx < 0 || fpIdx < 0 || pidIdx < 0 || portIdx < 0 || userIdx < 0 {
		t.Fatalf("missing expected fields in: %q", line)
	}
	if !(bindIdx < fpIdx && fpIdx < pidIdx && pidIdx < portIdx && portIdx < userIdx) {
		t.Errorf("event-specific fields not in alphabetical order in: %q", line)
	}
}

// TestJSONEnvelope_TrailingNewline asserts every emitted JSON line ends with
// exactly one newline.
func TestJSONEnvelope_TrailingNewline(t *testing.T) {
	l, buf := newTestLoggerFmt("", FormatJSON)
	l.ConnOpen("1.2.3.4:5")
	l.AuthOK("1.2.3.4:5", "alice", "password", "")
	out := buf.String()
	if !strings.HasSuffix(out, "\n") {
		t.Fatalf("output does not end with newline: %q", out)
	}
	// Each line (split on \n) except the final empty string should be
	// valid JSON.
	parts := strings.Split(out, "\n")
	for _, p := range parts[:len(parts)-1] {
		var m map[string]any
		if err := json.Unmarshal([]byte(p), &m); err != nil {
			t.Errorf("line is not valid JSON: %q", p)
		}
	}
}

// TestJSON_ErrorOmitsEmptyRemote mirrors TestErrorOmitsEmptyRemote for JSON.
func TestJSON_ErrorOmitsEmptyRemote(t *testing.T) {
	l, buf := newTestLoggerFmt("", FormatJSON)
	l.Error("disk full", "")
	line := lastLine(t, buf)
	var m map[string]any
	if err := json.Unmarshal([]byte(line), &m); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}
	if _, ok := m["remote"]; ok {
		t.Errorf("expected no remote key, got: %s", line)
	}
	if _, ok := m["message"]; !ok {
		t.Errorf("expected message key, got: %s", line)
	}
}

// TestJSON_StringEscape verifies that special characters in string fields
// round-trip correctly through JSON encoding.
func TestJSON_StringEscape(t *testing.T) {
	l, buf := newTestLoggerFmt("", FormatJSON)
	l.AuthOK("1.2.3.4:5", `user"with quote`, "password", "")
	line := lastLine(t, buf)
	var m map[string]any
	if err := json.Unmarshal([]byte(line), &m); err != nil {
		t.Fatalf("json.Unmarshal failed: %v\nline: %q", err, line)
	}
	if got, _ := m["user"].(string); got != `user"with quote` {
		t.Errorf("user field round-trip failed: got %q", got)
	}
}

// TestJSON_DurationAsFloatSeconds asserts that duration fields are emitted
// as float seconds, not as a time.Duration.String() form.
func TestJSON_DurationAsFloatSeconds(t *testing.T) {
	l, buf := newTestLoggerFmt("", FormatJSON)
	l.ConnClose("1.2.3.4:5", 1500*time.Millisecond)
	line := lastLine(t, buf)
	var m map[string]any
	if err := json.Unmarshal([]byte(line), &m); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}
	dur, ok := m["duration"].(float64)
	if !ok {
		t.Fatalf("duration field is not a float64, got %T: %v", m["duration"], m["duration"])
	}
	if dur != 1.5 {
		t.Errorf("duration = %v, want 1.5", dur)
	}
}

// TestJSON_DurationWholeSecondsHasDecimal asserts that whole-second durations
// are emitted with a ".0" suffix for visual distinction from integer counters.
func TestJSON_DurationWholeSecondsHasDecimal(t *testing.T) {
	l, buf := newTestLoggerFmt("", FormatJSON)
	l.ConnClose("1.2.3.4:5", 1*time.Second)
	line := lastLine(t, buf)
	if !strings.Contains(line, `"duration":1.0`) {
		t.Errorf("expected \"duration\":1.0 in: %q", line)
	}
}

// TestJSON_LineIsValidJSON exhaustively calls every event method and asserts
// each emitted line is valid JSON.
func TestJSON_LineIsValidJSON(t *testing.T) {
	l, buf := newTestLoggerFmt("", FormatJSON)
	l.Listening("0.0.0.0", 2222, "SHA256:abc", "alice", 4711, "password", 0)
	l.ConnOpen("1.2.3.4:5")
	l.ConnClose("1.2.3.4:5", time.Second)
	l.AuthOK("1.2.3.4:5", "alice", "password", "")
	l.AuthFail("1.2.3.4:5", "bob", "password", "bad-password", 2, 2*time.Second, "")
	l.Session("1.2.3.4:5", "shell")
	l.Reject("1.2.3.4:5", "x11")
	l.ShutdownSignal(1234, "HUP", "channel-close")
	l.DrainTimeout("1.2.3.4:5", "exec", 512)
	l.Error("something went wrong", "1.2.3.4:5")
	l.Error("global error", "")

	out := buf.String()
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	for i, line := range lines {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Errorf("line %d is not valid JSON: %q — %v", i, line, err)
		}
	}
}

// ---- JSON password scrub tests ----

// TestJSON_ScrubWithQuoteInPassword is the load-bearing test: a password
// containing a double-quote must not leak in its raw or JSON-escaped form.
func TestJSON_ScrubWithQuoteInPassword(t *testing.T) {
	const pw = "\"hello\"world" // contains literal double-quotes
	l, buf := newTestLoggerFmt(pw, FormatJSON)

	l.Listening(pw, 2222, pw, pw, 1, pw, 0)
	l.ConnOpen(pw)
	l.ConnClose(pw, time.Second)
	l.AuthOK(pw, pw, pw, pw)
	l.AuthFail(pw, pw, pw, pw, 1, time.Second, pw)
	l.Session(pw, pw)
	l.Reject(pw, pw)
	l.ShutdownSignal(1, pw, pw)
	l.DrainTimeout(pw, pw, 0)
	l.Error(pw, pw)

	out := buf.String()
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")

	// Every line must be valid JSON.
	for i, line := range lines {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Errorf("line %d is not valid JSON after scrub: %q — %v", i, line, err)
		}
	}

	// Raw password must not appear.
	if strings.Contains(out, pw) {
		t.Fatalf("raw password leaked in output:\n%s", out)
	}
	// JSON-encoded inner form must not appear.
	encodedInner := `\"hello\"world`
	if strings.Contains(out, encodedInner) {
		t.Fatalf("JSON-encoded password form leaked in output:\n%s", out)
	}
	// [REDACTED] must appear.
	if !strings.Contains(out, redacted) {
		t.Errorf("expected %q replacement in output:\n%s", redacted, out)
	}
}

// TestJSON_ScrubWithBackslashInPassword tests that passwords containing a
// backslash are scrubbed in both raw and encoded form.
func TestJSON_ScrubWithBackslashInPassword(t *testing.T) {
	const pw = `back\slash`
	l, buf := newTestLoggerFmt(pw, FormatJSON)

	l.AuthOK(pw, pw, pw, pw)
	l.Error(pw, pw)

	out := buf.String()
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	for i, line := range lines {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Errorf("line %d not valid JSON: %q — %v", i, line, err)
		}
	}
	if strings.Contains(out, pw) {
		t.Fatalf("raw password leaked:\n%s", out)
	}
	// Encoded form is back\\slash.
	encodedInner := `back\\slash`
	if strings.Contains(out, encodedInner) {
		t.Fatalf("encoded password leaked:\n%s", out)
	}
	if !strings.Contains(out, redacted) {
		t.Errorf("expected %q in output", redacted)
	}
}

// TestJSON_ScrubWithControlCharInPassword tests passwords containing a
// literal newline byte.
func TestJSON_ScrubWithControlCharInPassword(t *testing.T) {
	pw := "hi\nbye"
	l, buf := newTestLoggerFmt(pw, FormatJSON)

	l.AuthOK("1.2.3.4:5", pw, "password", "")

	out := buf.String()
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	for i, line := range lines {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Errorf("line %d not valid JSON: %q — %v", i, line, err)
		}
	}
	if strings.Contains(out, pw) {
		t.Fatalf("raw password leaked:\n%s", out)
	}
	if !strings.Contains(out, redacted) {
		t.Errorf("expected %q in output", redacted)
	}
}

// TestLogger_PubkeyEvents_AllFiveEmit calls all five Pubkey* methods and
// verifies each emits exactly one line containing the expected event name.
func TestLogger_PubkeyEvents_AllFiveEmit(t *testing.T) {
	cases := []struct {
		name      string
		wantEvent string
		emit      func(l *Logger)
	}{
		{
			name:      "PubkeyParseError",
			wantEvent: "pubkey-parse-error",
			emit:      func(l *Logger) { l.PubkeyParseError("/tmp/keys", 3, "bad line") },
		},
		{
			name:      "PubkeyOptionIgnored",
			wantEvent: "pubkey-option-ignored",
			emit:      func(l *Logger) { l.PubkeyOptionIgnored("/tmp/keys", 7, `command="ls"`) },
		},
		{
			name:      "PubkeyKeysMissing",
			wantEvent: "pubkey-keys-missing",
			emit:      func(l *Logger) { l.PubkeyKeysMissing("/tmp/keys") },
		},
		{
			name:      "PubkeyReloadOK",
			wantEvent: "pubkey-reload-ok",
			emit:      func(l *Logger) { l.PubkeyReloadOK("/tmp/keys", 2) },
		},
		{
			name:      "PubkeyReloadFailed",
			wantEvent: "pubkey-reload-failed",
			emit:      func(l *Logger) { l.PubkeyReloadFailed("/tmp/keys", "permission denied") },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l, buf := newTestLogger("")
			tc.emit(l)
			line := lastLine(t, buf)
			if !strings.Contains(line, tc.wantEvent) {
				t.Errorf("expected event %q in emitted line; got %q", tc.wantEvent, line)
			}
			if !eventLineRE.MatchString(line) {
				t.Errorf("line does not match envelope regex: %q", line)
			}
		})
	}
}

// TestLogger_PubkeyEvents_PasswordScrubStillApplies passes a password whose
// bytes appear inside an argument to each of the five Pubkey* methods and
// asserts that the scrub redacts the password in every emitted line.
func TestLogger_PubkeyEvents_PasswordScrubStillApplies(t *testing.T) {
	const pw = "hunter2"
	l, buf := newTestLogger(pw)

	// Embed the password in every string argument of every Pubkey* method.
	l.PubkeyParseError(pw, 1, pw)
	l.PubkeyOptionIgnored(pw, 2, pw)
	l.PubkeyKeysMissing(pw)
	l.PubkeyReloadOK(pw, 5)
	l.PubkeyReloadFailed(pw, pw)

	out := buf.String()
	if strings.Contains(out, pw) {
		t.Fatalf("password %q leaked into pubkey event output:\n%s", pw, out)
	}
	if !strings.Contains(out, redacted) {
		t.Errorf("expected %q redaction marker in output:\n%s", redacted, out)
	}
}

// TestLogfmt_PasswordScrubUnchanged is a regression guard: with the new
// scrubs [][]byte field, the existing logfmt password-scrub behavior must
// be byte-for-byte identical to the old l.password string field approach.
func TestLogfmt_PasswordScrubUnchanged(t *testing.T) {
	const pw = "hunter2"
	l, buf := newTestLoggerFmt(pw, FormatLogfmt)

	l.Listening(pw, 2222, pw, pw, 1, pw, 0)
	l.ConnOpen(pw)
	l.ConnClose(pw, time.Second)
	l.AuthOK(pw, pw, pw, pw)
	l.AuthFail(pw, pw, pw, pw, 1, time.Second, pw)
	l.Session(pw, pw)
	l.Reject(pw, pw)
	l.ShutdownSignal(1, pw, pw)
	l.DrainTimeout(pw, pw, 0)
	l.Error(pw, pw)

	out := buf.String()
	if strings.Contains(out, pw) {
		t.Fatalf("password leaked into logfmt output:\n%s", out)
	}
	if !strings.Contains(out, redacted) {
		t.Errorf("expected %q in logfmt output:\n%s", redacted, out)
	}
	// Verify logfmt shape is preserved (each line matches the envelope regex).
	for i, line := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
		if !eventLineRE.MatchString(line) {
			t.Errorf("line %d does not match envelope regex: %q", i, line)
		}
	}
}
