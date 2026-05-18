// Package logging emits the structured logfmt events listed in spec §9 and
// scrubs the configured password from every emitted line.
//
// Output format (spec §9):
//
//	RFC3339-timestamp LEVEL event key=value key="value with spaces"
//
// Values are double-quoted when they contain whitespace, '=', '"', or are
// empty; otherwise bare. Inside quoted values, '"' and '\\' are
// backslash-escaped. IPv4 and IPv6 literals contain only characters that do
// not trigger quoting and therefore appear unquoted.
//
// The Logger performs a literal byte-level scrub of the configured password
// from every line before it is written. The scrub is defense in depth — call
// sites must still avoid passing the password as an event field.
package logging

import (
	"bytes"
	"fmt"
	"io"
	"sync"
	"time"
)

// level constants per spec §9.
const (
	levelInfo  = "INFO"
	levelWarn  = "WARN"
	levelError = "ERROR"
)

// redacted is the replacement substituted for any occurrence of the configured
// password in an emitted line.
const redacted = "[REDACTED]"

// Logger emits the structured events defined in spec §9 to an underlying
// writer, applying a password scrub as a defense-in-depth guard.
//
// All methods are safe for concurrent use.
type Logger struct {
	mu       sync.Mutex
	w        io.Writer
	password string // empty disables the scrub
	now      func() time.Time
}

// New returns a Logger that writes events to w. password is the configured
// password value; every occurrence of that exact byte sequence in an emitted
// line is replaced with "[REDACTED]" before the line is written. If password
// is the empty string, no scrub is performed.
func New(w io.Writer, password string) *Logger {
	return &Logger{
		w:        w,
		password: password,
		now:      time.Now,
	}
}

// field is one key=value pair in an event. value is the raw string; the
// formatter decides quoting.
type field struct {
	key, value string
}

// emit serialises one event line and writes it through the scrub.
func (l *Logger) emit(level, event string, fields []field) {
	var buf bytes.Buffer
	buf.WriteString(l.now().Format(time.RFC3339))
	buf.WriteByte(' ')
	buf.WriteString(level)
	buf.WriteByte(' ')
	buf.WriteString(event)
	for _, f := range fields {
		buf.WriteByte(' ')
		buf.WriteString(f.key)
		buf.WriteByte('=')
		writeValue(&buf, f.value)
	}
	buf.WriteByte('\n')

	line := buf.Bytes()
	if l.password != "" {
		line = bytes.ReplaceAll(line, []byte(l.password), []byte(redacted))
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = l.w.Write(line)
}

// writeValue appends value to buf, applying the §9 quoting rules.
func writeValue(buf *bytes.Buffer, value string) {
	if needsQuoting(value) {
		buf.WriteByte('"')
		for i := 0; i < len(value); i++ {
			c := value[i]
			if c == '"' || c == '\\' {
				buf.WriteByte('\\')
			}
			buf.WriteByte(c)
		}
		buf.WriteByte('"')
		return
	}
	buf.WriteString(value)
}

// needsQuoting reports whether value must be double-quoted under §9: empty, or
// containing whitespace, '=' or '"'.
func needsQuoting(value string) bool {
	if value == "" {
		return true
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		switch c {
		case ' ', '\t', '\n', '\r', '=', '"':
			return true
		}
	}
	return false
}

// itoa formats a non-negative int (or any int — fmt handles the sign) as a
// decimal string. Using fmt.Sprintf keeps the implementation simple; the
// resulting digits never contain quoting-triggering characters.
func itoa(n int) string {
	return fmt.Sprintf("%d", n)
}

// --- Event methods (spec §9) ---------------------------------------------

// Listening emits the `listening` event (INFO) with the bound address, port,
// host-key fingerprint, expected username and PID.
func (l *Logger) Listening(bind string, port int, fingerprint, user string, pid int) {
	l.emit(levelInfo, "listening", []field{
		{"bind", bind},
		{"port", itoa(port)},
		{"fingerprint", fingerprint},
		{"user", user},
		{"pid", itoa(pid)},
	})
}

// ConnOpen emits the `conn-open` event (INFO).
func (l *Logger) ConnOpen(remote string) {
	l.emit(levelInfo, "conn-open", []field{
		{"remote", remote},
	})
}

// ConnClose emits the `conn-close` event (INFO).
func (l *Logger) ConnClose(remote string, duration time.Duration) {
	l.emit(levelInfo, "conn-close", []field{
		{"remote", remote},
		{"duration", duration.String()},
	})
}

// AuthOK emits the `auth-ok` event (INFO).
func (l *Logger) AuthOK(remote, user string) {
	l.emit(levelInfo, "auth-ok", []field{
		{"remote", remote},
		{"user", user},
	})
}

// AuthFail emits the `auth-fail` event (WARN). reason is "bad-user" or
// "bad-password"; attempt is the per-IP cumulative fail count after this
// failure; nextDelay is the sleep the next attempt from this IP will incur.
func (l *Logger) AuthFail(remote, user, reason string, attempt int, nextDelay time.Duration) {
	l.emit(levelWarn, "auth-fail", []field{
		{"remote", remote},
		{"user", user},
		{"reason", reason},
		{"attempt", itoa(attempt)},
		{"next_delay", nextDelay.String()},
	})
}

// Session emits the `session` event (INFO). kind is "shell", "exec" or "sftp".
func (l *Logger) Session(remote, kind string) {
	l.emit(levelInfo, "session", []field{
		{"remote", remote},
		{"kind", kind},
	})
}

// Reject emits the `reject` event (WARN). what identifies the rejected
// feature: "x11", "tcpip", "agent", "subsystem", "streamlocal", …
func (l *Logger) Reject(remote, what string) {
	l.emit(levelWarn, "reject", []field{
		{"remote", remote},
		{"what", what},
	})
}

// ShutdownSignal emits the `shutdown-signal` event (INFO). reason is
// "shutdown" or "channel-close" per spec §9.
func (l *Logger) ShutdownSignal(pgid int, sig, reason string) {
	l.emit(levelInfo, "shutdown-signal", []field{
		{"pgid", itoa(pgid)},
		{"sig", sig},
		{"reason", reason},
	})
}

// DrainTimeout emits the `drain-timeout` event (WARN). kind is "shell" or
// "exec"; bytesDropped is the count of post-exit bytes that were not
// delivered.
func (l *Logger) DrainTimeout(remote, kind string, bytesDropped int) {
	l.emit(levelWarn, "drain-timeout", []field{
		{"remote", remote},
		{"kind", kind},
		{"bytes_dropped", itoa(bytesDropped)},
	})
}

// Error emits the `error` event (ERROR). remote may be empty, in which case
// the field is omitted entirely.
func (l *Logger) Error(message, remote string) {
	fields := []field{{"message", message}}
	if remote != "" {
		fields = append(fields, field{"remote", remote})
	}
	l.emit(levelError, "error", fields)
}
