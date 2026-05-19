// Package logging emits the structured events listed in spec §9 to stdout
// in either logfmt (default) or JSON-Lines format, and scrubs the configured
// password from every emitted line.
//
// Output formats (spec §9):
//
//   - logfmt (default): RFC3339-timestamp LEVEL event key=value …
//     Values are double-quoted when they contain whitespace, '=', '"', or are
//     empty; otherwise bare. Inside quoted values, '"' and '\\' are
//     backslash-escaped.
//
//   - json: one JSON object per line. Field names match the logfmt keys.
//     See §9 for the full field-type table. The format is selected via
//     --log-format / MINISSHD_LOG_FORMAT; use ParseFormat to resolve.
//
// The Logger performs a literal byte-level scrub of the configured password
// from every line before it is written. The scrub is defense in depth — call
// sites must still avoid passing the password as an event field.
package logging

import (
	"bytes"
	"encoding/json"
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

// fieldKind encodes the semantic type of an event field so the JSON encoder
// can emit numeric values without re-parsing the pre-stringified value.
type fieldKind uint8

const (
	fieldString      fieldKind = iota
	fieldInt                   // num holds the value; value holds decimal form for logfmt
	fieldDurationSec           // dur holds the value; value holds Duration.String() for logfmt
	fieldBool                  // reserved; no current event uses it
)

// field is one key/value pair in an event. value is the canonical string form
// used by the logfmt encoder; kind/num/dur are consulted only by the JSON encoder.
type field struct {
	key   string
	value string // canonical string form (used for logfmt and as fallback)
	kind  fieldKind
	num   int64         // populated when kind == fieldInt
	dur   time.Duration // populated when kind == fieldDurationSec
}

// intField returns a field that emits as a JSON integer and a decimal logfmt value.
func intField(key string, n int) field {
	return field{key: key, kind: fieldInt, num: int64(n), value: itoa(n)}
}

// durField returns a field that emits as a JSON float-seconds and a logfmt Duration string.
func durField(key string, d time.Duration) field {
	return field{key: key, kind: fieldDurationSec, dur: d, value: d.String()}
}

// strField returns a string-typed field.
func strField(key, v string) field {
	return field{key: key, kind: fieldString, value: v}
}

// Logger emits the structured events defined in spec §9 to an underlying
// writer, applying a password scrub as a defense-in-depth guard.
//
// All methods are safe for concurrent use.
type Logger struct {
	mu     sync.Mutex
	w      io.Writer
	scrubs [][]byte // raw password bytes, then JSON-encoded-inner form (if different)
	now    func() time.Time
	format Format
}

// New returns a Logger that writes events to w in the specified format.
// password is the configured password value; every occurrence of that exact
// byte sequence (and its JSON-encoded form, for JSON output) in an emitted
// line is replaced with "[REDACTED]" before the line is written. If password
// is the empty string, no scrub is performed.
func New(w io.Writer, password string, format Format) *Logger {
	l := &Logger{w: w, format: format, now: time.Now}
	if password != "" {
		l.scrubs = [][]byte{[]byte(password)}
		// Also scrub the JSON-encoded inner form so passwords containing ",
		// \, or controls cannot leak as their escaped form in JSON output.
		if encoded, _ := json.Marshal(password); len(encoded) >= 2 {
			// Strip the leading/trailing quote bytes — we want the inner
			// escaped content, since string values appear inside quotes in
			// the output. Only add if it differs from the raw form (i.e.
			// the password contained an escapable byte).
			inner := encoded[1 : len(encoded)-1]
			if !bytes.Equal(inner, []byte(password)) {
				l.scrubs = append(l.scrubs, inner)
			}
		}
	}
	return l
}

// emit serialises one event line, runs the password scrub, and writes it.
func (l *Logger) emit(level, event string, fields []field) {
	var buf bytes.Buffer
	switch l.format {
	case FormatJSON:
		l.encodeJSON(&buf, level, event, fields)
	default:
		l.encodeLogfmt(&buf, level, event, fields)
	}
	line := buf.Bytes()
	if len(l.scrubs) > 0 {
		for _, s := range l.scrubs {
			line = bytes.ReplaceAll(line, s, []byte(redacted))
		}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = l.w.Write(line)
}

// encodeLogfmt writes the logfmt encoding of the event to buf.
func (l *Logger) encodeLogfmt(buf *bytes.Buffer, level, event string, fields []field) {
	buf.WriteString(l.now().Format(time.RFC3339))
	buf.WriteByte(' ')
	buf.WriteString(level)
	buf.WriteByte(' ')
	buf.WriteString(event)
	for _, f := range fields {
		buf.WriteByte(' ')
		buf.WriteString(f.key)
		buf.WriteByte('=')
		writeValue(buf, f.value)
	}
	buf.WriteByte('\n')
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
// host-key fingerprint, expected username, PID, auth method list, and public
// key count.
func (l *Logger) Listening(bind string, port int, fingerprint, user string, pid int, authMethods string, pubkeyCount int) {
	l.emit(levelInfo, "listening", []field{
		strField("bind", bind),
		intField("port", port),
		strField("fingerprint", fingerprint),
		strField("user", user),
		intField("pid", pid),
		strField("auth_methods", authMethods),
		intField("pubkey_count", pubkeyCount),
	})
}

// ConnOpen emits the `conn-open` event (INFO).
func (l *Logger) ConnOpen(remote string) {
	l.emit(levelInfo, "conn-open", []field{
		strField("remote", remote),
	})
}

// ConnClose emits the `conn-close` event (INFO).
func (l *Logger) ConnClose(remote string, duration time.Duration) {
	l.emit(levelInfo, "conn-close", []field{
		strField("remote", remote),
		durField("duration", duration),
	})
}

// AuthOK emits the `auth-ok` event (INFO). method is "password" or "publickey".
// fingerprint is the SHA-256 fingerprint of the presented key for publickey auth,
// or empty for password auth (in which case the field is omitted from output).
func (l *Logger) AuthOK(remote, user, method, fingerprint string) {
	fields := []field{
		strField("remote", remote),
		strField("user", user),
		strField("method", method),
	}
	if fingerprint != "" {
		fields = append(fields, strField("fingerprint", fingerprint))
	}
	l.emit(levelInfo, "auth-ok", fields)
}

// AuthFail emits the `auth-fail` event (WARN). method is "password" or "publickey";
// reason is "bad-user", "bad-password", or "bad-key"; attempt is the per-IP
// cumulative fail count after this failure; nextDelay is the sleep the next
// attempt from this IP will incur. fingerprint is the SHA-256 fingerprint of
// the presented key for publickey auth, or empty for password auth (omitted).
func (l *Logger) AuthFail(remote, user, method, reason string, attempt int, nextDelay time.Duration, fingerprint string) {
	fields := []field{
		strField("remote", remote),
		strField("user", user),
		strField("method", method),
		strField("reason", reason),
		intField("attempt", attempt),
		durField("next_delay", nextDelay),
	}
	if fingerprint != "" {
		fields = append(fields, strField("fingerprint", fingerprint))
	}
	l.emit(levelWarn, "auth-fail", fields)
}

// Session emits the `session` event (INFO). kind is "shell", "exec" or "sftp".
func (l *Logger) Session(remote, kind string) {
	l.emit(levelInfo, "session", []field{
		strField("remote", remote),
		strField("kind", kind),
	})
}

// Reject emits the `reject` event (WARN). what identifies the rejected
// feature: "x11", "tcpip", "agent", "subsystem", "streamlocal", …
func (l *Logger) Reject(remote, what string) {
	l.emit(levelWarn, "reject", []field{
		strField("remote", remote),
		strField("what", what),
	})
}

// ShutdownSignal emits the `shutdown-signal` event (INFO). reason is
// "shutdown" or "channel-close" per spec §9.
func (l *Logger) ShutdownSignal(pgid int, sig, reason string) {
	l.emit(levelInfo, "shutdown-signal", []field{
		intField("pgid", pgid),
		strField("sig", sig),
		strField("reason", reason),
	})
}

// DrainTimeout emits the `drain-timeout` event (WARN). kind is "shell" or
// "exec"; bytesDropped is the count of post-exit bytes that were not
// delivered.
func (l *Logger) DrainTimeout(remote, kind string, bytesDropped int) {
	l.emit(levelWarn, "drain-timeout", []field{
		strField("remote", remote),
		strField("kind", kind),
		intField("bytes_dropped", bytesDropped),
	})
}

// Error emits the `error` event (ERROR). remote may be empty, in which case
// the field is omitted entirely.
func (l *Logger) Error(message, remote string) {
	fields := []field{strField("message", message)}
	if remote != "" {
		fields = append(fields, strField("remote", remote))
	}
	l.emit(levelError, "error", fields)
}

// PubkeyParseError emits the `pubkey-parse-error` event (WARN). path is the
// authorized-keys file path; line is the 1-based line number; errMsg is the
// error returned by ssh.ParseAuthorizedKey.
func (l *Logger) PubkeyParseError(path string, line int, errMsg string) {
	l.emit(levelWarn, "pubkey-parse-error", []field{
		strField("path", path),
		intField("line", line),
		strField("error", errMsg),
	})
}

// PubkeyOptionIgnored emits the `pubkey-option-ignored` event (WARN). path is
// the file, line is the 1-based line number, option is the option string.
func (l *Logger) PubkeyOptionIgnored(path string, line int, option string) {
	l.emit(levelWarn, "pubkey-option-ignored", []field{
		strField("path", path),
		intField("line", line),
		strField("option", option),
	})
}

// PubkeyKeysMissing emits the `pubkey-keys-missing` event (WARN). path is the
// authorized-keys file that was absent at startup.
func (l *Logger) PubkeyKeysMissing(path string) {
	l.emit(levelWarn, "pubkey-keys-missing", []field{
		strField("path", path),
	})
}

// PubkeyReloadOK emits the `pubkey-reload-ok` event (INFO). path is the file
// path; pubkeyCount is the number of accepted keys after reload.
func (l *Logger) PubkeyReloadOK(path string, pubkeyCount int) {
	l.emit(levelInfo, "pubkey-reload-ok", []field{
		strField("path", path),
		intField("pubkey_count", pubkeyCount),
	})
}

// PubkeyReloadFailed emits the `pubkey-reload-failed` event (WARN). path is
// the file path; errMsg is the error or reason the reload was rejected.
func (l *Logger) PubkeyReloadFailed(path string, errMsg string) {
	l.emit(levelWarn, "pubkey-reload-failed", []field{
		strField("path", path),
		strField("error", errMsg),
	})
}
