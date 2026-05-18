package session

import (
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"syscall"
)

// filterEnv reports whether an SSH `env` request with key `name` should be
// honored. Per spec §8.1 step 4 the server accepts only `LANG` and any key
// beginning with `LC_`. Every other key is silently dropped — this is what
// blocks `LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`, and similar injection vectors.
func filterEnv(name string) bool {
	if name == "LANG" {
		return true
	}
	if strings.HasPrefix(name, "LC_") && len(name) > 3 {
		return true
	}
	return false
}

// isSftpSubsystem reports whether the given subsystem payload (already
// unwrapped from its RFC 4254 length prefix) names the sftp subsystem. The
// comparison is exact and case-sensitive per spec §7: any leading/trailing
// whitespace, different casing, or alternative names like "sftp-server" must
// be rejected.
func isSftpSubsystem(name string) bool {
	return name == "sftp"
}

// readSSHString parses an RFC 4255 §5 length-prefixed string from b and
// returns (value, rest, ok). The string is uint32-be length followed by
// length bytes.
func readSSHString(b []byte) (value string, rest []byte, ok bool) {
	if len(b) < 4 {
		return "", b, false
	}
	n := binary.BigEndian.Uint32(b[:4])
	if uint32(len(b)-4) < n {
		return "", b, false
	}
	return string(b[4 : 4+n]), b[4+n:], true
}

// readUint32 parses a big-endian uint32 from b.
func readUint32(b []byte) (v uint32, rest []byte, ok bool) {
	if len(b) < 4 {
		return 0, b, false
	}
	return binary.BigEndian.Uint32(b[:4]), b[4:], true
}

// ptyReq is the parsed payload of an RFC 4254 §6.2 pty-req.
type ptyReq struct {
	Term     string
	Cols     uint32
	Rows     uint32
	WidthPx  uint32
	HeightPx uint32
	// Modes blob is preserved verbatim; the implementation does not
	// re-apply modes (the PTY is opened with platform defaults), but the
	// field is parsed so a malformed payload is rejected.
	Modes []byte
}

// parsePtyReq parses RFC 4254 §6.2:
//
//	string  TERM
//	uint32  width chars
//	uint32  height rows
//	uint32  width px
//	uint32  height px
//	string  encoded terminal modes
func parsePtyReq(payload []byte) (*ptyReq, error) {
	r := &ptyReq{}
	var ok bool
	if r.Term, payload, ok = readSSHString(payload); !ok {
		return nil, fmt.Errorf("pty-req: malformed TERM")
	}
	if r.Cols, payload, ok = readUint32(payload); !ok {
		return nil, fmt.Errorf("pty-req: malformed cols")
	}
	if r.Rows, payload, ok = readUint32(payload); !ok {
		return nil, fmt.Errorf("pty-req: malformed rows")
	}
	if r.WidthPx, payload, ok = readUint32(payload); !ok {
		return nil, fmt.Errorf("pty-req: malformed width px")
	}
	if r.HeightPx, payload, ok = readUint32(payload); !ok {
		return nil, fmt.Errorf("pty-req: malformed height px")
	}
	var modes string
	if modes, payload, ok = readSSHString(payload); !ok {
		return nil, fmt.Errorf("pty-req: malformed modes")
	}
	r.Modes = []byte(modes)
	return r, nil
}

// winChange is the parsed payload of an RFC 4254 §6.7 window-change request.
type winChange struct {
	Cols     uint32
	Rows     uint32
	WidthPx  uint32
	HeightPx uint32
}

// parseWindowChange parses RFC 4254 §6.7:
//
//	uint32 width chars
//	uint32 height rows
//	uint32 width px
//	uint32 height px
func parseWindowChange(payload []byte) (*winChange, error) {
	r := &winChange{}
	var ok bool
	if r.Cols, payload, ok = readUint32(payload); !ok {
		return nil, fmt.Errorf("window-change: malformed cols")
	}
	if r.Rows, payload, ok = readUint32(payload); !ok {
		return nil, fmt.Errorf("window-change: malformed rows")
	}
	if r.WidthPx, payload, ok = readUint32(payload); !ok {
		return nil, fmt.Errorf("window-change: malformed width px")
	}
	if r.HeightPx, _, ok = readUint32(payload); !ok {
		return nil, fmt.Errorf("window-change: malformed height px")
	}
	return r, nil
}

// envReq is the parsed payload of an RFC 4254 §6.4 env request.
type envReq struct {
	Name  string
	Value string
}

// parseEnvReq parses (string name, string value).
func parseEnvReq(payload []byte) (*envReq, error) {
	r := &envReq{}
	var ok bool
	if r.Name, payload, ok = readSSHString(payload); !ok {
		return nil, fmt.Errorf("env: malformed name")
	}
	if r.Value, _, ok = readSSHString(payload); !ok {
		return nil, fmt.Errorf("env: malformed value")
	}
	return r, nil
}

// parseExecCommand parses a single SSH string payload (RFC 4254 §6.5).
func parseExecCommand(payload []byte) (string, error) {
	cmd, _, ok := readSSHString(payload)
	if !ok {
		return "", fmt.Errorf("exec: malformed command")
	}
	return cmd, nil
}

// parseSubsystemName parses the subsystem name from an RFC 4254 §6.5
// subsystem request payload (a single SSH string).
func parseSubsystemName(payload []byte) (string, error) {
	name, _, ok := readSSHString(payload)
	if !ok {
		return "", fmt.Errorf("subsystem: malformed name")
	}
	return name, nil
}

// signalName maps a POSIX signal to its SSH name per spec §13.2. Anything
// outside the documented set is reported as TERM with an
// `unmapped signal: ...` error message — the second return value — which the
// caller forwards as the `error_message` field of `exit-signal`.
func signalName(s os.Signal) (name string, errorMessage string) {
	sig, ok := s.(syscall.Signal)
	if !ok {
		return "TERM", fmt.Sprintf("unmapped signal: %v", s)
	}
	switch sig {
	case syscall.SIGHUP:
		return "HUP", ""
	case syscall.SIGINT:
		return "INT", ""
	case syscall.SIGQUIT:
		return "QUIT", ""
	case syscall.SIGILL:
		return "ILL", ""
	case syscall.SIGABRT:
		return "ABRT", ""
	case syscall.SIGFPE:
		return "FPE", ""
	case syscall.SIGKILL:
		return "KILL", ""
	case syscall.SIGSEGV:
		return "SEGV", ""
	case syscall.SIGPIPE:
		return "PIPE", ""
	case syscall.SIGALRM:
		return "ALRM", ""
	case syscall.SIGTERM:
		return "TERM", ""
	case syscall.SIGUSR1:
		return "USR1", ""
	case syscall.SIGUSR2:
		return "USR2", ""
	}
	return "TERM", fmt.Sprintf("unmapped signal: %s", sig)
}

// exitStatusPayload encodes the exit-status request payload (uint32 status).
func exitStatusPayload(code uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, code)
	return b
}

// exitSignalPayload encodes the exit-signal request payload:
//
//	string  signal name (without "SIG" prefix)
//	bool    core dumped
//	string  error message (ISO-10646 UTF-8)
//	string  language tag
func exitSignalPayload(sigName string, coreDumped bool, errMsg string) []byte {
	out := make([]byte, 0, 4+len(sigName)+1+4+len(errMsg)+4)
	out = appendSSHString(out, sigName)
	if coreDumped {
		out = append(out, 1)
	} else {
		out = append(out, 0)
	}
	out = appendSSHString(out, errMsg)
	out = appendSSHString(out, "")
	return out
}

// appendSSHString appends a length-prefixed SSH string to dst.
func appendSSHString(dst []byte, s string) []byte {
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(s)))
	dst = append(dst, lenBuf[:]...)
	dst = append(dst, s...)
	return dst
}
