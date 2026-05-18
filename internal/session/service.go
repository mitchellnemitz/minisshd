// Package session implements interactive shell, exec, and SFTP session
// handling per spec §8.
//
// A Service value carries the configured shell path and the structured
// logger. Service.Handle takes ownership of an accepted "session" channel:
// it reads SSH requests off the channel, dispatches pty-req / env /
// window-change / shell / exec / subsystem per RFC 4254, spawns and
// supervises the child, and delivers exit-status or exit-signal back to
// the client before closing the channel.
//
// Concurrency: every Service method is safe to call from multiple
// goroutines simultaneously. Each Handle invocation owns its own
// per-session state — no Service-wide mutable state exists.
package session

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/mitchellnemitz/minisshd/internal/logging"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// drainCap is the wall-clock cap on post-exit output drain (spec §8.1
// step 5 / §8.2 step 4). Anything past this is dropped and a
// drain-timeout event is logged.
const drainCap = 2 * time.Second

// shutdownGrace is the wall-clock cap between SIGHUP and SIGKILL when the
// server is shutting down or the channel has been closed (spec §8 Signal
// handling).
const shutdownGrace = 5 * time.Second

// Service handles SSH session channels per spec §8.
type Service struct {
	// Shell is the path to the configured login shell (e.g. /bin/zsh).
	// Service treats this path as already-validated (spec §2 step 4).
	Shell string

	// Log is the structured logger used for `session`, `reject`,
	// `shutdown-signal`, `drain-timeout`, and `error` events.
	Log *logging.Logger

	// allocPTY is the PTY allocator; tests override it. Nil means use
	// the production creack/pty allocator.
	allocPTY ptyAllocator

	// sftpHandler runs the SFTP subsystem. Tests override it. Nil means
	// use the production pkg/sftp handler.
	sftpHandler func(ch ssh.Channel) error

	// hostEnv supplies the server-process environment used to build the
	// child env (spec §8.1 step 4). Tests override it; nil means use
	// os.Environ.
	hostEnv func() []string
}

// sessionState holds the per-channel state accumulated across requests
// before a shell/exec/subsystem starts the child.
type sessionState struct {
	mu        sync.Mutex
	pty       *ptyReq
	ptyMaster ptyHandle
	ptySlave  *os.File
	envFromCh map[string]string // accepted env requests
	started   bool              // first shell/exec/subsystem decided
}

// Handle takes ownership of an accepted session channel and runs the
// per-spec request loop until the channel and child have both settled.
// ctx cancellation triggers the §8 shutdown path (SIGHUP, 5 s, SIGKILL).
// remoteAddr is included in log events as the `remote` field.
func (s *Service) Handle(ctx context.Context, ch ssh.Channel, reqs <-chan *ssh.Request, remoteAddr string) {
	st := &sessionState{envFromCh: map[string]string{}}

	closeOnce := &sync.Once{}
	closeChannel := func() {
		closeOnce.Do(func() { _ = ch.Close() })
	}
	defer closeChannel()

	// Phase 1: handle pre-spawn requests (pty-req, env, window-change,
	// rejected types). Returns when one of shell/exec/subsystem has
	// committed the session (or when the request stream closes).
	var pending *spawn

	for req := range reqs {
		done, sp := s.preSpawnDispatch(req, st, remoteAddr)
		if sp != nil {
			pending = sp
		}
		if done {
			break
		}
	}
	if pending == nil {
		// Channel closed without a shell/exec/subsystem starting;
		// release any allocated PTY and return.
		st.mu.Lock()
		if st.ptyMaster != nil {
			_ = st.ptyMaster.Close()
		}
		if st.ptySlave != nil {
			_ = st.ptySlave.Close()
		}
		st.mu.Unlock()
		return
	}

	// Phase 2: dispatch to the appropriate runner.
	switch pending.kind {
	case "sftp":
		_ = pending.req.Reply(true, nil)
		s.Log.Session(remoteAddr, "sftp")
		s.runSftp(ctx, ch, reqs, remoteAddr)
	case "shell", "exec":
		// Start the child first; if start fails reply false and
		// emit error per spec §11.
		runner, startErr := s.startChild(ch, pending.cmd, st, remoteAddr)
		if startErr != nil {
			_ = pending.req.Reply(false, nil)
			s.Log.Error("child spawn failed: "+startErr.Error(), remoteAddr)
			_, _ = ch.SendRequest("exit-status", false, exitStatusPayload(127))
			return
		}
		_ = pending.req.Reply(true, nil)
		s.Log.Session(remoteAddr, pending.kind)
		s.runChild(ctx, ch, reqs, st, runner, pending.kind, remoteAddr)
	}
}

// spawn carries the decision from preSpawnDispatch back to Handle.
type spawn struct {
	kind string // "shell" | "exec" | "sftp"
	cmd  *exec.Cmd
	req  *ssh.Request
}

// preSpawnDispatch routes a single request received before any
// shell/exec/subsystem has committed the channel. It returns done=true
// once one of those three has been parsed and prepared; the caller breaks
// out of its loop and the prepared *spawn is dispatched. If the request
// is unhandleable (malformed, second pty-req, etc.) done=false continues
// the loop.
func (s *Service) preSpawnDispatch(req *ssh.Request, st *sessionState, remoteAddr string) (done bool, sp *spawn) {
	switch req.Type {
	case "pty-req":
		s.handlePtyReq(req, st, remoteAddr)
		return false, nil
	case "env":
		s.handleEnv(req, st)
		return false, nil
	case "window-change":
		s.handleWindowChange(req, st)
		return false, nil
	case "shell":
		cmd := s.prepareShell(st)
		return true, &spawn{kind: "shell", cmd: cmd, req: req}
	case "exec":
		command, err := parseExecCommand(req.Payload)
		if err != nil {
			_ = req.Reply(false, nil)
			s.Log.Error("exec: "+err.Error(), remoteAddr)
			return false, nil
		}
		cmd := s.prepareExec(st, command)
		return true, &spawn{kind: "exec", cmd: cmd, req: req}
	case "subsystem":
		name, err := parseSubsystemName(req.Payload)
		if err != nil || !isSftpSubsystem(name) {
			_ = req.Reply(false, nil)
			s.Log.Reject(remoteAddr, "subsystem")
			return false, nil
		}
		return true, &spawn{kind: "sftp", req: req}
	case "signal":
		// want_reply=false per RFC 4254 §6.9; silently drop.
		return false, nil
	case "x11-req":
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		s.Log.Reject(remoteAddr, "x11")
		return false, nil
	case "auth-agent-req@openssh.com":
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		s.Log.Reject(remoteAddr, "agent")
		return false, nil
	default:
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		return false, nil
	}
}

// prepareShell builds the *exec.Cmd for a `shell` request per spec §8.1.
// argv[0] is "-<basename>" (login-shell convention).
func (s *Service) prepareShell(st *sessionState) *exec.Cmd {
	cmd := exec.Command(s.Shell)
	cmd.Args = []string{"-" + filepath.Base(s.Shell)}
	cmd.Env = s.buildEnv(st)
	return cmd
}

// prepareExec builds the *exec.Cmd for an `exec` request per spec §8.2.
// argv[0] is bare (no hyphen prefix); the shell receives `-c <command>`.
func (s *Service) prepareExec(st *sessionState, command string) *exec.Cmd {
	cmd := exec.Command(s.Shell, "-c", command)
	cmd.Args = []string{filepath.Base(s.Shell), "-c", command}
	cmd.Env = s.buildEnv(st)
	return cmd
}

// handlePtyReq parses an RFC 4254 §6.2 pty-req and allocates a PTY pair.
// Per spec §11 a PTY allocation failure replies false but keeps the
// channel open so the client can still fall back to non-PTY exec.
func (s *Service) handlePtyReq(req *ssh.Request, st *sessionState, remoteAddr string) {
	st.mu.Lock()
	defer st.mu.Unlock()

	if st.started {
		_ = req.Reply(false, nil)
		return
	}
	if st.pty != nil {
		_ = req.Reply(false, nil)
		return
	}
	pr, err := parsePtyReq(req.Payload)
	if err != nil {
		_ = req.Reply(false, nil)
		s.Log.Error("pty-req: "+err.Error(), remoteAddr)
		return
	}
	alloc := s.allocPTY
	if alloc == nil {
		alloc = creackOpen
	}
	master, slave, err := alloc()
	if err != nil {
		_ = req.Reply(false, nil)
		s.Log.Error("pty allocation failed: "+err.Error(), remoteAddr)
		return
	}
	_ = master.Setsize(pr.Cols, pr.Rows, pr.WidthPx, pr.HeightPx)
	st.pty = pr
	st.ptyMaster = master
	st.ptySlave = slave
	_ = req.Reply(true, nil)
}

// handleEnv parses an env request and stores it if the name passes the
// §8.1 step 4 filter. The reply is always true so clients cannot probe
// which names were accepted.
func (s *Service) handleEnv(req *ssh.Request, st *sessionState) {
	st.mu.Lock()
	defer st.mu.Unlock()

	if st.started {
		_ = req.Reply(false, nil)
		return
	}
	e, err := parseEnvReq(req.Payload)
	if err != nil {
		_ = req.Reply(true, nil)
		return
	}
	if filterEnv(e.Name) {
		st.envFromCh[e.Name] = e.Value
	}
	_ = req.Reply(true, nil)
}

// handleWindowChange parses RFC 4254 §6.7 and resizes the PTY if
// allocated. Per the RFC `want_reply` is false; we still honor it if set.
//
// The Setsize call is performed while holding st.mu so it cannot race with
// the cleanup path in runChild that clears and closes st.ptyMaster.
func (s *Service) handleWindowChange(req *ssh.Request, st *sessionState) {
	wc, err := parseWindowChange(req.Payload)
	if err != nil {
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		return
	}
	st.mu.Lock()
	if st.ptyMaster != nil {
		_ = st.ptyMaster.Setsize(wc.Cols, wc.Rows, wc.WidthPx, wc.HeightPx)
	}
	st.mu.Unlock()
	if req.WantReply {
		_ = req.Reply(true, nil)
	}
}

// runSftp services the sftp subsystem on ch. It returns when the server
// has finished (channel EOF or error). Meanwhile a small goroutine
// rejects any subsequent requests on the channel.
func (s *Service) runSftp(ctx context.Context, ch ssh.Channel, reqs <-chan *ssh.Request, remoteAddr string) {
	// Reject any additional channel requests (second shell, exec, etc.).
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.rejectExtraRequests(reqs)
	}()

	handler := s.sftpHandler
	if handler == nil {
		handler = defaultSftpHandler
	}
	servErr := make(chan error, 1)
	go func() {
		servErr <- handler(ch)
	}()

	select {
	case err := <-servErr:
		if err != nil && err != io.EOF {
			s.Log.Error("sftp: "+err.Error(), remoteAddr)
		}
	case <-ctx.Done():
		// Closing the channel forces the sftp server to return.
		_ = ch.Close()
		<-servErr
	}
	<-done
}

// defaultSftpHandler is the production SFTP handler — pkg/sftp with
// default options, server rooted at / per spec §8 SFTP.
func defaultSftpHandler(ch ssh.Channel) error {
	srv, err := sftp.NewServer(ch)
	if err != nil {
		return err
	}
	defer func() { _ = srv.Close() }()
	if err := srv.Serve(); err != nil && err != io.EOF {
		return err
	}
	return nil
}

// childRunner bundles the state of a started child process.
type childRunner struct {
	cmd     *exec.Cmd
	pgid    int
	master  ptyHandle
	closers []io.Closer
	// drainDones close once each stdout/stderr/master copy goroutine
	// has finished forwarding output to the channel.
	drainDones []chan struct{}
}

// startChild starts cmd attached either to a PTY (if one was allocated)
// or to pipes. Output goroutines are spawned and reflected via the
// returned childRunner.
func (s *Service) startChild(ch ssh.Channel, cmd *exec.Cmd, st *sessionState, remoteAddr string) (*childRunner, error) {
	st.mu.Lock()
	master := st.ptyMaster
	slave := st.ptySlave
	hasPty := st.pty != nil
	st.started = true
	st.mu.Unlock()

	if hasPty {
		if err := startWithPTY(cmd, slave); err != nil {
			_ = master.Close()
			return nil, err
		}
		pgid := cmd.Process.Pid

		mDone := make(chan struct{})
		go func() {
			defer close(mDone)
			_, _ = io.Copy(ch, master)
		}()
		go func() {
			_, _ = io.Copy(master, ch)
		}()
		return &childRunner{
			cmd:        cmd,
			pgid:       pgid,
			master:     master,
			closers:    []io.Closer{master},
			drainDones: []chan struct{}{mDone},
		}, nil
	}

	// Non-PTY path: assign ch / ch.Stderr() directly so os/exec owns the
	// stdout/stderr copy goroutines. cmd.Wait() joins those goroutines
	// before returning, eliminating the StdoutPipe/StderrPipe drain race
	// where Wait would close the pipe FD before our io.Copy goroutines
	// finished draining the kernel buffer. (See os/exec docs on
	// StdoutPipe: "Wait will close the pipe after seeing the command
	// exit, so most callers need not close it themselves; it is thus
	// incorrect to call Wait before all reads from the pipe have
	// completed.") Stdin still uses a pipe because the SSH channel may
	// stay open after the child closes its stdin, and we want to be
	// able to close the child's stdin half independently.
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stdout = ch
	cmd.Stderr = ch.Stderr()
	cmd.SysProcAttr = newPipeSysProcAttr()
	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		return nil, err
	}
	pgid := cmd.Process.Pid

	go func() {
		_, _ = io.Copy(stdin, ch)
		_ = stdin.Close()
	}()
	// No drainDones for stdout/stderr: cmd.Wait() blocks until os/exec's
	// internal copies from the child's stdout/stderr into ch/ch.Stderr()
	// have completed, so by the time runChild's drain() is called there
	// is nothing left to wait on for the non-PTY path. The 2 s drainCap
	// backstop in spec §8.2 step 4 is effectively enforced by the
	// surrounding ctx-driven select that bounds cmd.Wait().
	return &childRunner{
		cmd:  cmd,
		pgid: pgid,
	}, nil
}

// runChild supervises a started child until either the child exits, ctx
// fires, or the channel closes. After settling it drains output (2 s
// cap) and sends exit-status or exit-signal — except when the channel
// closed from the client, in which case no exit is sent.
func (s *Service) runChild(
	ctx context.Context,
	ch ssh.Channel,
	reqs <-chan *ssh.Request,
	st *sessionState,
	runner *childRunner,
	kind, remoteAddr string,
) {
	// Reject second shell/exec/subsystem; honor window-change/signal.
	// Returns when reqs closes (channel half-close from peer).
	chanClosed := make(chan struct{})
	go func() {
		defer close(chanClosed)
		s.processInflightRequests(reqs, st)
	}()

	waitErr := make(chan error, 1)
	go func() {
		waitErr <- runner.cmd.Wait()
	}()

	killed := false
	select {
	case <-ctx.Done():
		s.signalAndKill(runner.pgid, "shutdown")
		killed = true
		<-waitErr
	case <-chanClosed:
		// Client closed the channel before child exit; SIGHUP path.
		s.signalAndKill(runner.pgid, "channel-close")
		killed = true
		<-waitErr
	case <-waitErr:
		// Child exited on its own.
	}

	// Drain output capped at drainCap.
	s.drain(remoteAddr, kind, runner.drainDones)

	// Clear st.ptyMaster under the mutex before closing it so an
	// in-flight handleWindowChange cannot race against Close on the
	// same *os.File.
	if runner.master != nil {
		st.mu.Lock()
		st.ptyMaster = nil
		st.mu.Unlock()
	}
	for _, c := range runner.closers {
		_ = c.Close()
	}

	if !killed {
		s.sendExit(ch, runner.cmd.ProcessState)
		// Spec §8.1 step 6 / §8.2 step 5: server initiates the
		// channel close after sending exit-status/exit-signal.
		// Real OpenSSH and golang.org/x/crypto/ssh clients do NOT
		// close the channel themselves after exit; the server-side
		// close lets the library propagate EOF on reqs and unblocks
		// the <-chanClosed wait below.
		_ = ch.Close()
	}
	// Wait for chanClosed if not already; drains any leftover requests.
	<-chanClosed
}

// processInflightRequests handles requests received while the child is
// running. It rejects a second shell/exec/subsystem, applies
// window-change, drops signal, and rejects everything else. Returns when
// reqs closes.
func (s *Service) processInflightRequests(reqs <-chan *ssh.Request, st *sessionState) {
	for req := range reqs {
		switch req.Type {
		case "window-change":
			s.handleWindowChange(req, st)
		case "signal":
			// drop per spec §8
		case "shell", "exec", "subsystem":
			_ = req.Reply(false, nil)
		default:
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}
}

// rejectExtraRequests rejects any request that arrives after the sftp
// subsystem has been activated. Returns when reqs closes.
func (s *Service) rejectExtraRequests(reqs <-chan *ssh.Request) {
	for req := range reqs {
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
	}
}

// signalAndKill sends SIGHUP to the process group identified by pgid,
// waits up to shutdownGrace for the group to drain, then sends SIGKILL.
// Both signals are logged via ShutdownSignal.
func (s *Service) signalAndKill(pgid int, reason string) {
	_ = syscall.Kill(-pgid, syscall.SIGHUP)
	s.Log.ShutdownSignal(pgid, "HUP", reason)

	deadline := time.Now().Add(shutdownGrace)
	for time.Now().Before(deadline) {
		if err := syscall.Kill(-pgid, 0); err != nil {
			// ESRCH: the entire group has gone.
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	_ = syscall.Kill(-pgid, syscall.SIGKILL)
	s.Log.ShutdownSignal(pgid, "KILL", reason)
}

// drain waits for each output-copy goroutine to finish, capped at
// drainCap. When the cap fires, the drain-timeout event is logged. We do
// not have a cheap way to count post-cap bytes (io.Copy has already moved
// them); log 0 per the task brief.
func (s *Service) drain(remoteAddr, kind string, drainDones []chan struct{}) {
	if len(drainDones) == 0 {
		return
	}
	timer := time.NewTimer(drainCap)
	defer timer.Stop()

	remaining := append([]chan struct{}(nil), drainDones...)
	for len(remaining) > 0 {
		// Build a select dynamically: timer + first pending channel.
		select {
		case <-timer.C:
			s.Log.DrainTimeout(remoteAddr, kind, 0)
			return
		case <-remaining[0]:
			remaining = remaining[1:]
		}
	}
}

// sendExit translates cmd.ProcessState into exit-status or exit-signal
// per spec §8.1 step 6 / §8.2 step 5.
func (s *Service) sendExit(ch ssh.Channel, ps *os.ProcessState) {
	if ps == nil {
		_, _ = ch.SendRequest("exit-status", false, exitStatusPayload(0))
		return
	}
	ws, ok := ps.Sys().(syscall.WaitStatus)
	if !ok {
		_, _ = ch.SendRequest("exit-status", false, exitStatusPayload(uint32(ps.ExitCode())))
		return
	}
	if ws.Signaled() {
		name, errMsg := signalName(ws.Signal())
		_, _ = ch.SendRequest("exit-signal", false, exitSignalPayload(name, ws.CoreDump(), errMsg))
		return
	}
	if ws.Exited() {
		_, _ = ch.SendRequest("exit-status", false, exitStatusPayload(uint32(ws.ExitStatus())))
		return
	}
	_, _ = ch.SendRequest("exit-status", false, exitStatusPayload(0))
}

// buildEnv constructs the child environment per spec §8.1 step 4 (and
// §8.2 step 3 — TERM only when a PTY is attached).
func (s *Service) buildEnv(st *sessionState) []string {
	host := s.hostEnv
	if host == nil {
		host = os.Environ
	}
	src := host()

	picked := map[string]string{}
	pick := func(name string) {
		for _, kv := range src {
			if eq := indexEqual(kv); eq > 0 {
				if kv[:eq] == name {
					picked[name] = kv[eq+1:]
				}
			}
		}
	}
	pick("HOME")
	pick("USER")
	pick("LOGNAME")
	pick("SHELL")
	pick("PATH")
	for _, kv := range src {
		eq := indexEqual(kv)
		if eq <= 0 {
			continue
		}
		k := kv[:eq]
		if filterEnv(k) {
			picked[k] = kv[eq+1:]
		}
	}
	// Channel-supplied env overrides server env for matching keys.
	for k, v := range st.envFromCh {
		picked[k] = v
	}
	if st.pty != nil && st.pty.Term != "" {
		picked["TERM"] = st.pty.Term
	}

	out := make([]string, 0, len(picked))
	for k, v := range picked {
		out = append(out, k+"="+v)
	}
	return out
}

// indexEqual returns the index of the first '=' in s, or -1 if absent.
func indexEqual(s string) int {
	for i := 0; i < len(s); i++ {
		if s[i] == '=' {
			return i
		}
	}
	return -1
}
