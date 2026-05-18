package session

import (
	"encoding/binary"
	"strings"
	"syscall"
	"testing"
)

// TestFilterEnv covers spec §8.1 step 4 and §13.2 "Env-var filter".
func TestFilterEnv(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{"LANG", true},
		{"LC_ALL", true},
		{"LC_TIME", true},
		{"LC_CTYPE", true},
		{"LC_", false}, // bare prefix is not a valid LC_* key
		{"LANGUAGE", false},
		{"LD_PRELOAD", false},
		{"DYLD_INSERT_LIBRARIES", false},
		{"PATH", false},
		{"HOME", false},
		{"SHELL", false},
		{"FOO", false},
		{"", false},
		{"lang", false},   // case-sensitive
		{"lc_all", false}, // case-sensitive
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := filterEnv(c.name); got != c.want {
				t.Fatalf("filterEnv(%q) = %v, want %v", c.name, got, c.want)
			}
		})
	}
}

// TestIsSftpSubsystem covers spec §7 strict subsystem comparison.
func TestIsSftpSubsystem(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"sftp", true},
		{"SFTP", false},
		{"Sftp", false},
		{" sftp", false},
		{"sftp ", false},
		{"sftp-server", false},
		{"", false},
		{"sftp\x00", false},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			if got := isSftpSubsystem(c.in); got != c.want {
				t.Fatalf("isSftpSubsystem(%q) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}

// TestSignalName covers spec §13.2 POSIX→SSH mapping.
func TestSignalName(t *testing.T) {
	type want struct {
		name string
		err  string
	}
	cases := []struct {
		sig  syscall.Signal
		want want
	}{
		{syscall.SIGHUP, want{"HUP", ""}},
		{syscall.SIGINT, want{"INT", ""}},
		{syscall.SIGQUIT, want{"QUIT", ""}},
		{syscall.SIGILL, want{"ILL", ""}},
		{syscall.SIGABRT, want{"ABRT", ""}},
		{syscall.SIGFPE, want{"FPE", ""}},
		{syscall.SIGKILL, want{"KILL", ""}},
		{syscall.SIGSEGV, want{"SEGV", ""}},
		{syscall.SIGPIPE, want{"PIPE", ""}},
		{syscall.SIGALRM, want{"ALRM", ""}},
		{syscall.SIGTERM, want{"TERM", ""}},
		{syscall.SIGUSR1, want{"USR1", ""}},
		{syscall.SIGUSR2, want{"USR2", ""}},
	}
	for _, c := range cases {
		t.Run(c.want.name, func(t *testing.T) {
			n, e := signalName(c.sig)
			if n != c.want.name || e != c.want.err {
				t.Fatalf("signalName(%v) = (%q, %q), want (%q, %q)",
					c.sig, n, e, c.want.name, c.want.err)
			}
		})
	}
}

// TestSignalNameUnmapped asserts the fallback branch returns TERM with an
// `unmapped signal:` error message.
func TestSignalNameUnmapped(t *testing.T) {
	n, e := signalName(syscall.Signal(99))
	if n != "TERM" {
		t.Fatalf("name = %q, want TERM", n)
	}
	if !strings.HasPrefix(e, "unmapped signal:") {
		t.Fatalf("errorMessage = %q, want prefix 'unmapped signal:'", e)
	}
}

// TestParsePtyReq parses a well-formed RFC 4254 §6.2 payload and a few
// malformed variants.
func TestParsePtyReq(t *testing.T) {
	payload := makeSSHString("xterm-256color")
	payload = appendUint32(payload, 132)
	payload = appendUint32(payload, 47)
	payload = appendUint32(payload, 0)
	payload = appendUint32(payload, 0)
	payload = append(payload, makeSSHString("\x00")...)

	pr, err := parsePtyReq(payload)
	if err != nil {
		t.Fatalf("parsePtyReq: %v", err)
	}
	if pr.Term != "xterm-256color" {
		t.Fatalf("term = %q", pr.Term)
	}
	if pr.Cols != 132 || pr.Rows != 47 {
		t.Fatalf("dims = %d×%d", pr.Cols, pr.Rows)
	}

	if _, err := parsePtyReq(nil); err == nil {
		t.Fatalf("expected error on empty payload")
	}
	if _, err := parsePtyReq([]byte{0, 0, 0, 10, 'x'}); err == nil {
		t.Fatalf("expected error on truncated payload")
	}
}

// TestParseEnvReq covers the env-request parser.
func TestParseEnvReq(t *testing.T) {
	p := append(makeSSHString("LC_ALL"), makeSSHString("en_US.UTF-8")...)
	e, err := parseEnvReq(p)
	if err != nil {
		t.Fatalf("parseEnvReq: %v", err)
	}
	if e.Name != "LC_ALL" || e.Value != "en_US.UTF-8" {
		t.Fatalf("got (%q,%q)", e.Name, e.Value)
	}
	if _, err := parseEnvReq([]byte{0, 0}); err == nil {
		t.Fatalf("expected error")
	}
}

// TestParseWindowChange covers the window-change parser.
func TestParseWindowChange(t *testing.T) {
	p := appendUint32(nil, 100)
	p = appendUint32(p, 30)
	p = appendUint32(p, 800)
	p = appendUint32(p, 600)
	wc, err := parseWindowChange(p)
	if err != nil {
		t.Fatalf("parseWindowChange: %v", err)
	}
	if wc.Cols != 100 || wc.Rows != 30 || wc.WidthPx != 800 || wc.HeightPx != 600 {
		t.Fatalf("got %+v", wc)
	}
	if _, err := parseWindowChange([]byte{0, 0, 0}); err == nil {
		t.Fatalf("expected error")
	}
}

// TestParseExecCommand covers the exec-command parser.
func TestParseExecCommand(t *testing.T) {
	got, err := parseExecCommand(makeSSHString("echo hi"))
	if err != nil {
		t.Fatalf("parseExecCommand: %v", err)
	}
	if got != "echo hi" {
		t.Fatalf("got %q", got)
	}
	if _, err := parseExecCommand([]byte{0, 0}); err == nil {
		t.Fatalf("expected error")
	}
}

// TestParseSubsystemName covers the subsystem-name parser.
func TestParseSubsystemName(t *testing.T) {
	got, err := parseSubsystemName(makeSSHString("sftp"))
	if err != nil {
		t.Fatalf("parseSubsystemName: %v", err)
	}
	if got != "sftp" {
		t.Fatalf("got %q", got)
	}
}

// TestExitStatusPayload asserts the wire layout.
func TestExitStatusPayload(t *testing.T) {
	p := exitStatusPayload(127)
	if len(p) != 4 {
		t.Fatalf("len = %d", len(p))
	}
	if binary.BigEndian.Uint32(p) != 127 {
		t.Fatalf("code = %d", binary.BigEndian.Uint32(p))
	}
}

// TestExitSignalPayload asserts the wire layout matches RFC 4254 §6.10.
func TestExitSignalPayload(t *testing.T) {
	p := exitSignalPayload("TERM", true, "killed")
	// string "TERM" | byte 1 | string "killed" | string ""
	name, rest, ok := readSSHString(p)
	if !ok || name != "TERM" {
		t.Fatalf("name = %q ok=%v", name, ok)
	}
	if len(rest) < 1 || rest[0] != 1 {
		t.Fatalf("core dumped flag = %v", rest)
	}
	rest = rest[1:]
	msg, rest, ok := readSSHString(rest)
	if !ok || msg != "killed" {
		t.Fatalf("msg = %q ok=%v", msg, ok)
	}
	tag, _, ok := readSSHString(rest)
	if !ok || tag != "" {
		t.Fatalf("tag = %q ok=%v", tag, ok)
	}
}

// --- payload-builder helpers used by tests ---------------------------------

func makeSSHString(s string) []byte {
	out := make([]byte, 4+len(s))
	binary.BigEndian.PutUint32(out[:4], uint32(len(s)))
	copy(out[4:], s)
	return out
}

func appendUint32(b []byte, v uint32) []byte {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], v)
	return append(b, buf[:]...)
}
