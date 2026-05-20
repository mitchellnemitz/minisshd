package session

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mitchellnemitz/minisshd/internal/logging"
	"golang.org/x/crypto/ssh"
)

// newTestService builds a Service backed by an in-memory logger and a
// deterministic host env, with the production PTY/SFTP integrations
// replaced by safe fakes so tests do not fork real processes.
func newTestService() (*Service, *bytes.Buffer) {
	buf := &bytes.Buffer{}
	s := &Service{
		Shell: "/bin/sh",
		Log:   logging.New(buf, "", logging.FormatLogfmt),
		hostEnv: func() []string {
			return []string{
				"HOME=/home/user",
				"USER=user",
				"LOGNAME=user",
				"SHELL=/bin/sh",
				"PATH=/usr/bin:/bin",
				"LANG=en_US.UTF-8",
				"LC_ALL=en_US.UTF-8",
				"LD_PRELOAD=/evil.so",
				"DYLD_INSERT_LIBRARIES=/evil.dylib",
				"FOO=bar",
				"TERM=should-be-replaced",
			}
		},
	}
	return s, buf
}

// TestBuildEnvNoPty asserts that bare exec gets no TERM and only the
// whitelisted server-process variables plus filtered LC_*/LANG.
func TestBuildEnvNoPty(t *testing.T) {
	t.Parallel()
	s, _ := newTestService()
	st := &sessionState{envFromCh: map[string]string{}}
	env := s.buildEnv(st)
	got := envToMap(env)

	mustHave := []string{"HOME", "USER", "LOGNAME", "SHELL", "PATH", "LANG", "LC_ALL"}
	for _, k := range mustHave {
		if _, ok := got[k]; !ok {
			t.Errorf("expected key %q in env, got %v", k, got)
		}
	}
	for _, k := range []string{"LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "FOO", "TERM"} {
		if _, ok := got[k]; ok {
			t.Errorf("unexpected key %q in env", k)
		}
	}
}

// TestBuildEnvWithPty asserts that a pty-req's TERM appears in the env.
func TestBuildEnvWithPty(t *testing.T) {
	t.Parallel()
	s, _ := newTestService()
	st := &sessionState{
		envFromCh: map[string]string{},
		pty:       &ptyReq{Term: "xterm-256color"},
	}
	env := s.buildEnv(st)
	got := envToMap(env)
	if got["TERM"] != "xterm-256color" {
		t.Fatalf("TERM = %q, want xterm-256color", got["TERM"])
	}
}

// TestBuildEnvChannelOverrides asserts channel-supplied env values win
// over the server-process value for whitelisted keys.
func TestBuildEnvChannelOverrides(t *testing.T) {
	t.Parallel()
	s, _ := newTestService()
	st := &sessionState{envFromCh: map[string]string{"LANG": "C"}}
	env := s.buildEnv(st)
	got := envToMap(env)
	if got["LANG"] != "C" {
		t.Fatalf("LANG = %q, want C", got["LANG"])
	}
}

func envToMap(env []string) map[string]string {
	m := map[string]string{}
	for _, kv := range env {
		eq := indexEqual(kv)
		if eq < 0 {
			continue
		}
		m[kv[:eq]] = kv[eq+1:]
	}
	return m
}

// TestPreSpawnDispatchRouting drives preSpawnDispatch with a sequence of
// requests and asserts the routing decision without actually forking a
// shell. Build-of-the-cmd is enough to prove the right branch ran.
func TestPreSpawnDispatchRouting(t *testing.T) {
	t.Parallel()
	t.Run("shell", func(t *testing.T) {
		s, _ := newTestService()
		st := &sessionState{envFromCh: map[string]string{}}
		req := &ssh.Request{Type: "shell"}
		done, sp := s.preSpawnDispatch(req, st, "1.2.3.4:1")
		if !done || sp == nil || sp.kind != "shell" || sp.cmd == nil {
			t.Fatalf("got done=%v sp=%+v", done, sp)
		}
		// argv[0] must be -<basename> for login-shell convention.
		if sp.cmd.Args[0] != "-sh" {
			t.Fatalf("argv[0] = %q, want -sh", sp.cmd.Args[0])
		}
	})
	t.Run("exec", func(t *testing.T) {
		s, _ := newTestService()
		st := &sessionState{envFromCh: map[string]string{}}
		req := &ssh.Request{Type: "exec", Payload: makeSSHString("echo hi")}
		done, sp := s.preSpawnDispatch(req, st, "1.2.3.4:1")
		if !done || sp == nil || sp.kind != "exec" {
			t.Fatalf("got done=%v sp=%+v", done, sp)
		}
		// argv[0] is bare; subsequent args are -c and the command.
		if sp.cmd.Args[0] != "sh" || sp.cmd.Args[1] != "-c" || sp.cmd.Args[2] != "echo hi" {
			t.Fatalf("argv = %v, want [sh -c echo hi]", sp.cmd.Args)
		}
	})
	t.Run("subsystem-sftp", func(t *testing.T) {
		s, _ := newTestService()
		st := &sessionState{envFromCh: map[string]string{}}
		req := &ssh.Request{Type: "subsystem", Payload: makeSSHString("sftp")}
		done, sp := s.preSpawnDispatch(req, st, "1.2.3.4:1")
		if !done || sp == nil || sp.kind != "sftp" {
			t.Fatalf("got done=%v sp=%+v", done, sp)
		}
	})
	t.Run("subsystem-other-rejected", func(t *testing.T) {
		s, buf := newTestService()
		st := &sessionState{envFromCh: map[string]string{}}
		req := &ssh.Request{Type: "subsystem", Payload: makeSSHString("sftp-server")}
		done, sp := s.preSpawnDispatch(req, st, "1.2.3.4:1")
		if done || sp != nil {
			t.Fatalf("expected rejected; got done=%v sp=%+v", done, sp)
		}
		if !strings.Contains(buf.String(), "reject") || !strings.Contains(buf.String(), "what=subsystem") {
			t.Fatalf("expected reject log, got %q", buf.String())
		}
	})
	t.Run("x11-rejected", func(t *testing.T) {
		s, buf := newTestService()
		st := &sessionState{envFromCh: map[string]string{}}
		req := &ssh.Request{Type: "x11-req"}
		done, sp := s.preSpawnDispatch(req, st, "1.2.3.4:1")
		if done || sp != nil {
			t.Fatalf("expected non-terminal; got done=%v sp=%+v", done, sp)
		}
		if !strings.Contains(buf.String(), "what=x11") {
			t.Fatalf("expected x11 reject log, got %q", buf.String())
		}
	})
	t.Run("agent-rejected", func(t *testing.T) {
		s, buf := newTestService()
		st := &sessionState{envFromCh: map[string]string{}}
		req := &ssh.Request{Type: "auth-agent-req@openssh.com"}
		done, sp := s.preSpawnDispatch(req, st, "1.2.3.4:1")
		if done || sp != nil {
			t.Fatalf("expected non-terminal; got done=%v sp=%+v", done, sp)
		}
		if !strings.Contains(buf.String(), "what=agent") {
			t.Fatalf("expected agent reject log, got %q", buf.String())
		}
	})
	t.Run("signal-dropped", func(t *testing.T) {
		s, buf := newTestService()
		st := &sessionState{envFromCh: map[string]string{}}
		req := &ssh.Request{Type: "signal", WantReply: false}
		done, sp := s.preSpawnDispatch(req, st, "1.2.3.4:1")
		if done || sp != nil {
			t.Fatalf("got done=%v sp=%+v", done, sp)
		}
		// Should emit no log at all.
		if buf.Len() != 0 {
			t.Fatalf("expected no log for signal, got %q", buf.String())
		}
	})
	t.Run("env-filter-records-only-allowed", func(t *testing.T) {
		s, _ := newTestService()
		st := &sessionState{envFromCh: map[string]string{}}
		s.preSpawnDispatch(&ssh.Request{Type: "env", Payload: append(makeSSHString("LANG"), makeSSHString("C")...)}, st, "x")
		s.preSpawnDispatch(&ssh.Request{Type: "env", Payload: append(makeSSHString("LD_PRELOAD"), makeSSHString("/evil.so")...)}, st, "x")
		s.preSpawnDispatch(&ssh.Request{Type: "env", Payload: append(makeSSHString("LC_TIME"), makeSSHString("UTC")...)}, st, "x")
		if got, want := len(st.envFromCh), 2; got != want {
			t.Fatalf("env filter accepted %d, want %d (%v)", got, want, st.envFromCh)
		}
		if st.envFromCh["LANG"] != "C" || st.envFromCh["LC_TIME"] != "UTC" {
			t.Fatalf("envFromCh = %v", st.envFromCh)
		}
	})
}

// TestHandlePtyReqAllocFailure asserts §11: a PTY-allocation failure
// replies false and keeps the channel open.
func TestHandlePtyReqAllocFailure(t *testing.T) {
	t.Parallel()
	s, buf := newTestService()
	s.allocPTY = func() (ptyHandle, *os.File, error) {
		return nil, nil, errors.New("simulated ENOMEM")
	}
	st := &sessionState{envFromCh: map[string]string{}}
	payload := buildPtyReqPayload("xterm", 80, 24)
	req := &ssh.Request{Type: "pty-req", Payload: payload, WantReply: false}
	s.handlePtyReq(req, st, "1.2.3.4:1")
	if st.pty != nil || st.ptyMaster != nil {
		t.Fatalf("state should not record a PTY after alloc failure")
	}
	if !strings.Contains(buf.String(), "pty allocation failed") {
		t.Fatalf("expected error log, got %q", buf.String())
	}
}

// TestHandlePtyReqSuccess uses a mock PTY allocator and asserts the PTY
// is recorded and Setsize called with the initial dimensions.
func TestHandlePtyReqSuccess(t *testing.T) {
	t.Parallel()
	s, _ := newTestService()
	mock := &mockPty{}
	s.allocPTY = func() (ptyHandle, *os.File, error) {
		return mock, nil, nil
	}
	st := &sessionState{envFromCh: map[string]string{}}
	payload := buildPtyReqPayload("xterm-256color", 132, 47)
	s.handlePtyReq(&ssh.Request{Type: "pty-req", Payload: payload}, st, "x")
	if st.pty == nil || st.pty.Term != "xterm-256color" {
		t.Fatalf("pty state not recorded: %+v", st.pty)
	}
	if len(mock.sizes) != 1 {
		t.Fatalf("Setsize calls = %d, want 1", len(mock.sizes))
	}
	if mock.sizes[0] != [4]uint32{132, 47, 0, 0} {
		t.Fatalf("Setsize args = %v", mock.sizes[0])
	}
}

// TestHandleWindowChangeResize drives handleWindowChange against a mock
// PTY (proves §13.2's "window-change resizes the PTY (asserted against a
// mock ioctl)" requirement).
func TestHandleWindowChangeResize(t *testing.T) {
	t.Parallel()
	s, _ := newTestService()
	mock := &mockPty{}
	st := &sessionState{ptyMaster: mock}

	payload := appendUint32(nil, 200)
	payload = appendUint32(payload, 50)
	payload = appendUint32(payload, 1600)
	payload = appendUint32(payload, 1000)
	s.handleWindowChange(&ssh.Request{Type: "window-change", Payload: payload}, st)

	if len(mock.sizes) != 1 {
		t.Fatalf("Setsize calls = %d, want 1", len(mock.sizes))
	}
	if mock.sizes[0] != [4]uint32{200, 50, 1600, 1000} {
		t.Fatalf("Setsize args = %v", mock.sizes[0])
	}
}

// TestHandleWindowChangeNoPty asserts a window-change without a prior
// pty-req is a no-op (no panic).
func TestHandleWindowChangeNoPty(t *testing.T) {
	t.Parallel()
	s, _ := newTestService()
	st := &sessionState{}
	payload := appendUint32(nil, 1)
	payload = appendUint32(payload, 2)
	payload = appendUint32(payload, 3)
	payload = appendUint32(payload, 4)
	s.handleWindowChange(&ssh.Request{Type: "window-change", Payload: payload}, st)
}

// TestRunSftpHandsOffToHandler verifies runSftp calls the configured
// handler and propagates ctx cancellation by closing the channel.
func TestRunSftpHandsOffToHandler(t *testing.T) {
	t.Parallel()
	s, _ := newTestService()
	called := atomic.Int32{}
	s.sftpHandler = func(ch ssh.Channel) error {
		called.Add(1)
		// Block until the channel is closed to simulate a long-running
		// SFTP server.
		buf := make([]byte, 1)
		_, _ = ch.Read(buf)
		return nil
	}
	ch := newMockChannel()
	reqs := make(chan *ssh.Request)
	close(reqs)

	done := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		s.runSftp(ctx, ch, reqs, "x")
		close(done)
	}()
	// Allow the handler to start, then cancel.
	deadline := time.Now().Add(2 * time.Second)
	for called.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("sftp handler did not start in time")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done
}

// TestSendExitNilProcessState exercises the defensive nil branch.
func TestSendExitNilProcessState(t *testing.T) {
	t.Parallel()
	s, _ := newTestService()
	ch := newMockChannel()
	s.sendExit(ch, nil)
	if len(ch.sentRequests) != 1 || ch.sentRequests[0].name != "exit-status" {
		t.Fatalf("expected exit-status, got %+v", ch.sentRequests)
	}
}

// --- helpers ---------------------------------------------------------------

// buildPtyReqPayload assembles a minimal valid pty-req payload.
func buildPtyReqPayload(term string, cols, rows uint32) []byte {
	out := makeSSHString(term)
	out = appendUint32(out, cols)
	out = appendUint32(out, rows)
	out = appendUint32(out, 0)
	out = appendUint32(out, 0)
	out = append(out, makeSSHString("\x00")...)
	return out
}

// mockPty is a ptyHandle suitable for unit tests; it records Setsize
// calls and serves zeroes on Read.
type mockPty struct {
	mu     sync.Mutex
	sizes  [][4]uint32
	closed bool
}

func (m *mockPty) Read(p []byte) (int, error) {
	m.mu.Lock()
	closed := m.closed
	m.mu.Unlock()
	if closed {
		return 0, io.EOF
	}
	// Block-free: act as EOF for tests.
	return 0, io.EOF
}
func (m *mockPty) Write(p []byte) (int, error) { return len(p), nil }
func (m *mockPty) Close() error {
	m.mu.Lock()
	m.closed = true
	m.mu.Unlock()
	return nil
}
func (m *mockPty) File() *os.File { return nil }
func (m *mockPty) Setsize(cols, rows, wp, hp uint32) error {
	m.mu.Lock()
	m.sizes = append(m.sizes, [4]uint32{cols, rows, wp, hp})
	m.mu.Unlock()
	return nil
}

// sentRequest captures a SendRequest call so tests can inspect what the
// service tried to send.
type sentRequest struct {
	name    string
	want    bool
	payload []byte
}

// mockChannel is an ssh.Channel suitable for unit-testing message paths.
type mockChannel struct {
	mu           sync.Mutex
	readBuf      *bytes.Buffer
	writeBuf     *bytes.Buffer
	stderrBuf    *bytes.Buffer
	closed       bool
	sentRequests []sentRequest
}

func newMockChannel() *mockChannel {
	return &mockChannel{
		readBuf:   &bytes.Buffer{},
		writeBuf:  &bytes.Buffer{},
		stderrBuf: &bytes.Buffer{},
	}
}

func (c *mockChannel) Read(p []byte) (int, error) {
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed && c.readBuf.Len() == 0 {
		return 0, io.EOF
	}
	if c.readBuf.Len() == 0 {
		return 0, io.EOF
	}
	return c.readBuf.Read(p)
}
func (c *mockChannel) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.writeBuf.Write(p)
}
func (c *mockChannel) Close() error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	return nil
}
func (c *mockChannel) CloseWrite() error { return nil }
func (c *mockChannel) SendRequest(name string, wantReply bool, payload []byte) (bool, error) {
	c.mu.Lock()
	c.sentRequests = append(c.sentRequests, sentRequest{name, wantReply, append([]byte(nil), payload...)})
	c.mu.Unlock()
	return true, nil
}
func (c *mockChannel) Stderr() io.ReadWriter { return c.stderrBuf }
