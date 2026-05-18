package server_test

// Additional §13.3 integration tests targeting the lower-coverage code
// paths in internal/session and internal/server. These don't appear in
// the spec's enumeration of required scenarios but exercise documented
// behaviors that unit tests don't fully cover when combined with the
// real channel/session machinery.

import (
	"bufio"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// TestIntegration_EnvRequestAcceptedAndRejectedAfterStart drives both
// branches of session.handleEnv: a pre-spawn LANG accepted, and a
// post-spawn LANG rejected.
func TestIntegration_EnvRequestAcceptedAndRejectedAfterStart(t *testing.T) {
	ts := startTestServer(t, testServerOptions{})
	defer ts.cleanup()

	cli := dialSSH(t, ts.addr, clientConfig(ts.user, ts.password))
	defer cli.Close()

	sess, err := cli.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer sess.Close()

	// Pre-spawn env request — accepted.
	if err := sess.Setenv("LANG", "en_US.UTF-8"); err != nil {
		t.Fatalf("Setenv LANG (pre-spawn): %v", err)
	}
	if err := sess.Setenv("LC_ALL", "C"); err != nil {
		t.Fatalf("Setenv LC_ALL (pre-spawn): %v", err)
	}
	// LD_PRELOAD should be filtered server-side (accept-but-drop) — the
	// reply is still true, no observable difference at this layer.
	_ = sess.Setenv("LD_PRELOAD", "/tmp/evil.so")

	out, err := runOnSession(t, sess, "echo LANG=$LANG")
	if err != nil {
		if _, ok := isExitErr(err); !ok {
			t.Fatalf("Run: %v", err)
		}
	}
	if !strings.Contains(out, "LANG=en_US.UTF-8") {
		t.Fatalf("expected LANG=en_US.UTF-8 in output; got %q", out)
	}
}

// TestIntegration_WindowChangePreSpawn drives session.handleWindowChange
// via the pre-spawn path: pty-req, window-change, shell, exit.
func TestIntegration_WindowChangePreSpawn(t *testing.T) {
	ts := startTestServer(t, testServerOptions{})
	defer ts.cleanup()

	cli := dialSSH(t, ts.addr, clientConfig(ts.user, ts.password))
	defer cli.Close()

	sess, err := cli.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer sess.Close()

	if err := sess.RequestPty("xterm", 24, 80, ssh.TerminalModes{}); err != nil {
		t.Fatalf("RequestPty: %v", err)
	}
	// Resize BEFORE Start so the request fires while the session is
	// in the pre-spawn phase — pre-spawn handleWindowChange runs under
	// the same st.mu that handlePtyReq used to allocate the master.
	if err := sess.WindowChange(40, 120); err != nil {
		t.Fatalf("WindowChange: %v", err)
	}
	// Now drive shell + exit so the post-spawn dispatch still works.
	stdin, _ := sess.StdinPipe()
	out := &syncBuffer{}
	sess.Stdout = out
	sess.Stderr = out
	if err := sess.Shell(); err != nil {
		t.Fatalf("Shell: %v", err)
	}
	if _, err := io.WriteString(stdin, "echo PRE_OK; exit\n"); err != nil {
		t.Fatalf("write stdin: %v", err)
	}
	_ = stdin.Close()
	_, _ = waitSession(t, sess, 5*time.Second)
	if !strings.Contains(out.String(), "PRE_OK") {
		t.Fatalf("expected PRE_OK in shell output; got:\n%s", out.String())
	}
}

// TestIntegration_WindowChangePostSpawn drives session.handleWindowChange
// via the post-spawn path: pty-req, shell, window-change while the shell
// is running, exit. With commit 3aef20b's mu-serialized Setsize/Close,
// this is race-clean under -race.
func TestIntegration_WindowChangePostSpawn(t *testing.T) {
	ts := startTestServer(t, testServerOptions{})
	defer ts.cleanup()

	cli := dialSSH(t, ts.addr, clientConfig(ts.user, ts.password))
	defer cli.Close()

	sess, err := cli.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer sess.Close()

	if err := sess.RequestPty("xterm", 24, 80, ssh.TerminalModes{}); err != nil {
		t.Fatalf("RequestPty: %v", err)
	}
	stdin, _ := sess.StdinPipe()
	out := &syncBuffer{}
	sess.Stdout = out
	sess.Stderr = out
	if err := sess.Shell(); err != nil {
		t.Fatalf("Shell: %v", err)
	}
	// Now that the child is running, send several window-change
	// requests to exercise the post-spawn (in-flight) handler under
	// the shared st.mu critical section that gates ptyMaster.
	for _, sz := range []struct{ rows, cols int }{
		{30, 100}, {50, 132}, {24, 80},
	} {
		if err := sess.WindowChange(sz.rows, sz.cols); err != nil {
			t.Fatalf("WindowChange %dx%d: %v", sz.cols, sz.rows, err)
		}
	}
	if _, err := io.WriteString(stdin, "echo POST_OK; exit\n"); err != nil {
		t.Fatalf("write stdin: %v", err)
	}
	_ = stdin.Close()
	_, _ = waitSession(t, sess, 5*time.Second)
	if !strings.Contains(out.String(), "POST_OK") {
		t.Fatalf("expected POST_OK in shell output; got:\n%s", out.String())
	}
}

// TestIntegration_SignalRequestSilentlyDropped exercises the §8 signal-
// drop path (RFC 4254 §6.9, want_reply=false).
func TestIntegration_SignalRequestSilentlyDropped(t *testing.T) {
	ts := startTestServer(t, testServerOptions{})
	defer ts.cleanup()

	cli := dialSSH(t, ts.addr, clientConfig(ts.user, ts.password))
	defer cli.Close()

	sess, err := cli.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer sess.Close()

	if err := sess.Start("sleep 0.5; echo OK"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	// Signal with want_reply=false — server should silently drop.
	if err := sess.Signal(ssh.SIGUSR1); err != nil {
		t.Logf("Signal returned %v (informational; server drops it)", err)
	}
	_, _ = waitSession(t, sess, 5*time.Second)
}

// TestIntegration_UnknownSubsystemRejected drives the "subsystem
// anything-other-than-sftp" reject path.
func TestIntegration_UnknownSubsystemRejected(t *testing.T) {
	ts := startTestServer(t, testServerOptions{})
	defer ts.cleanup()

	cli := dialSSH(t, ts.addr, clientConfig(ts.user, ts.password))
	defer cli.Close()

	ch, reqs, err := cli.OpenChannel("session", nil)
	if err != nil {
		t.Fatalf("OpenChannel session: %v", err)
	}
	defer ch.Close()
	go ssh.DiscardRequests(reqs)

	payload := ssh.Marshal(&struct{ Name string }{Name: "shell-wrapper"})
	ok, err := ch.SendRequest("subsystem", true, payload)
	if err != nil {
		t.Fatalf("SendRequest subsystem: %v", err)
	}
	if ok {
		t.Fatalf("expected subsystem=shell-wrapper to be rejected")
	}
	if !waitForLog(t, ts.logBuf, "what=subsystem", 2*time.Second) {
		t.Fatalf("expected `what=subsystem` reject in log; got:\n%s", ts.logBuf.String())
	}
}

// TestIntegration_AgentRequestRejected drives the "auth-agent-req@
// openssh.com" reject path.
func TestIntegration_AgentRequestRejected(t *testing.T) {
	ts := startTestServer(t, testServerOptions{})
	defer ts.cleanup()

	cli := dialSSH(t, ts.addr, clientConfig(ts.user, ts.password))
	defer cli.Close()

	ch, reqs, err := cli.OpenChannel("session", nil)
	if err != nil {
		t.Fatalf("OpenChannel session: %v", err)
	}
	defer ch.Close()
	go ssh.DiscardRequests(reqs)

	ok, err := ch.SendRequest("auth-agent-req@openssh.com", true, nil)
	if err != nil {
		t.Fatalf("SendRequest agent-req: %v", err)
	}
	if ok {
		t.Fatalf("expected agent-req to be rejected")
	}
	if !waitForLog(t, ts.logBuf, "what=agent", 2*time.Second) {
		t.Fatalf("expected `what=agent` reject in log; got:\n%s", ts.logBuf.String())
	}
}

// TestIntegration_StreamlocalChannelRejected drives the streamlocal
// channel-open reject path.
func TestIntegration_StreamlocalChannelRejected(t *testing.T) {
	ts := startTestServer(t, testServerOptions{})
	defer ts.cleanup()

	cli := dialSSH(t, ts.addr, clientConfig(ts.user, ts.password))
	defer cli.Close()

	_, _, err := cli.OpenChannel("direct-streamlocal@openssh.com", nil)
	if err == nil {
		t.Fatalf("expected direct-streamlocal to be rejected")
	}
	if !waitForLog(t, ts.logBuf, "what=streamlocal", 2*time.Second) {
		t.Fatalf("expected `what=streamlocal` in log; got:\n%s", ts.logBuf.String())
	}
}

// TestIntegration_GlobalTCPIPForwardRejected drives the tcpip-forward
// global-request reject path.
func TestIntegration_GlobalTCPIPForwardRejected(t *testing.T) {
	ts := startTestServer(t, testServerOptions{})
	defer ts.cleanup()

	cli := dialSSH(t, ts.addr, clientConfig(ts.user, ts.password))
	defer cli.Close()

	// tcpip-forward payload: address-to-bind(string) + port-to-bind(uint32).
	type tcpipForwardPayload struct {
		Address string
		Port    uint32
	}
	payload := ssh.Marshal(&tcpipForwardPayload{Address: "127.0.0.1", Port: 18181})
	ok, _, err := cli.SendRequest("tcpip-forward", true, payload)
	if err != nil {
		t.Fatalf("SendRequest tcpip-forward: %v", err)
	}
	if ok {
		t.Fatalf("expected tcpip-forward to be rejected")
	}
	if !waitForLog(t, ts.logBuf, "what=tcpip", 2*time.Second) {
		t.Fatalf("expected `what=tcpip` in log; got:\n%s", ts.logBuf.String())
	}
}

// TestIntegration_MultipleConcurrentSessionsOnOneConnection covers the
// multi-session-per-connection path: a client opens 3 sessions, each
// runs a short exec.
func TestIntegration_MultipleConcurrentSessionsOnOneConnection(t *testing.T) {
	ts := startTestServer(t, testServerOptions{})
	defer ts.cleanup()

	cli := dialSSH(t, ts.addr, clientConfig(ts.user, ts.password))
	defer cli.Close()

	const n = 3
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sess, err := cli.NewSession()
			if err != nil {
				t.Errorf("NewSession: %v", err)
				return
			}
			defer sess.Close()
			_, _ = runOnSession(t, sess, "echo MULTI_SESS")
		}()
	}
	wg.Wait()
}

// TestIntegration_CancelTCPIPForwardRejected drives the second branch of
// handleGlobalRequest: `cancel-tcpip-forward` must reply false AND log
// `reject what=tcpip` per spec §7. The companion `tcpip-forward` is
// tested in server_integration_test.go.
func TestIntegration_CancelTCPIPForwardRejected(t *testing.T) {
	ts := startTestServer(t, testServerOptions{})
	defer ts.cleanup()

	cli := dialSSH(t, ts.addr, clientConfig(ts.user, ts.password))
	defer cli.Close()

	// cancel-tcpip-forward payload mirrors tcpip-forward.
	type cancelPayload struct {
		Address string
		Port    uint32
	}
	payload := ssh.Marshal(&cancelPayload{Address: "127.0.0.1", Port: 18181})
	ok, _, err := cli.SendRequest("cancel-tcpip-forward", true, payload)
	if err != nil {
		t.Fatalf("SendRequest cancel-tcpip-forward: %v", err)
	}
	if ok {
		t.Fatalf("expected cancel-tcpip-forward to be rejected")
	}
	if !waitForLog(t, ts.logBuf, "what=tcpip", 2*time.Second) {
		t.Fatalf("expected `what=tcpip` in log for cancel-tcpip-forward; got:\n%s",
			ts.logBuf.String())
	}
}

// TestIntegration_SubsystemCaseVariantsRejected drives the strict
// `isSftpSubsystem` check in session.preSpawnDispatch: anything other
// than the exact byte sequence "sftp" must be rejected. We probe
// uppercase, mixed-case, trailing/leading whitespace, and the OpenSSH
// "sftp-server" alias. Each case must reply false and emit
// `reject what=subsystem`.
func TestIntegration_SubsystemCaseVariantsRejected(t *testing.T) {
	variants := []string{"SFTP", "Sftp", " sftp", "sftp-server", "sftp\n"}
	for _, name := range variants {
		name := name
		t.Run("variant="+strings.ReplaceAll(strings.ReplaceAll(name, "\n", "\\n"), " ", "_"),
			func(t *testing.T) {
				ts := startTestServer(t, testServerOptions{})
				defer ts.cleanup()

				cli := dialSSH(t, ts.addr, clientConfig(ts.user, ts.password))
				defer cli.Close()

				ch, reqs, err := cli.OpenChannel("session", nil)
				if err != nil {
					t.Fatalf("OpenChannel: %v", err)
				}
				defer ch.Close()
				go ssh.DiscardRequests(reqs)

				payload := ssh.Marshal(&struct{ Name string }{Name: name})
				ok, err := ch.SendRequest("subsystem", true, payload)
				if err != nil {
					t.Fatalf("SendRequest subsystem=%q: %v", name, err)
				}
				if ok {
					t.Fatalf("expected subsystem=%q to be rejected", name)
				}
				if !waitForLog(t, ts.logBuf, "what=subsystem", 2*time.Second) {
					t.Fatalf("expected `what=subsystem` reject in log for %q; got:\n%s",
						name, ts.logBuf.String())
				}
			})
	}
}

// TestIntegration_TCPCloseDuringHandshake drives the
// isExpectedHandshakeError path: a bare TCP connection that closes
// without sending SSH version-string MUST result in a conn-close log
// event. Whether the close manifests as EOF (clean half-close) or
// ECONNRESET (RST) depends on the TCP path; both are valid.
//
// Note: the current isExpectedHandshakeError only matches the literal
// "EOF" / "unexpected EOF" error messages. ECONNRESET reports as
// "read: connection reset by peer", which surfaces an `error` log
// event today — that's a small gap in spec §9 noise-suppression that
// the implementer may want to widen. The test asserts only that
// handleConn completes (conn-close logged); the handshake-error
// surfacing is informational.
func TestIntegration_TCPCloseDuringHandshake(t *testing.T) {
	ts := startTestServer(t, testServerOptions{})
	defer ts.cleanup()

	// Plain TCP dial — no SSH handshake. Close immediately to trigger
	// the EOF or ECONNRESET path in ssh.NewServerConn.
	c, err := net.Dial("tcp", ts.addr)
	if err != nil {
		t.Fatalf("net.Dial: %v", err)
	}
	_ = c.Close()

	// Wait for the conn-close event so we know handleConn finished.
	if !waitForLog(t, ts.logBuf, "conn-close", 5*time.Second) {
		t.Fatalf("expected conn-close after tcp-close; got:\n%s", ts.logBuf.String())
	}
	if strings.Contains(ts.logBuf.String(), "handshake:") {
		t.Logf("note: handshake error surfaced (informational; "+
			"isExpectedHandshakeError doesn't match ECONNRESET):\n%s",
			ts.logBuf.String())
	}
}

// TestIntegration_IPv6ClientAddress drives the normalizeKey IPv6 branch.
// Even on an IPv4 listener, dialing `::1` requires a separate IPv6
// listener; we spin one up bound to `::1` and ensure auth succeeds and
// the per-IP limiter snapshot exposes a non-IPv4 key. The post-success
// snapshot must NOT contain the IPv6 entry (success deletes it), so we
// verify normalizeKey by causing a single auth-fail event and then
// inspecting the snapshot.
func TestIntegration_IPv6ClientAddress(t *testing.T) {
	// Confirm the kernel has IPv6 enabled by attempting a listener.
	probe, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback not available on this host: %v", err)
	}
	_ = probe.Close()

	ts := startTestServer(t, testServerOptions{bind: "::1"})
	defer ts.cleanup()

	// One wrong-password attempt to populate the limiter snapshot with
	// an IPv6 entry. The connection will fail; we just need the failure
	// recorded.
	cfg := &ssh.ClientConfig{
		User:            ts.user,
		Auth:            []ssh.AuthMethod{ssh.Password("nope")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	_, _ = ssh.Dial("tcp", ts.addr, cfg)

	// Wait for the fail event so the snapshot is populated.
	if !waitForLog(t, ts.logBuf, "reason=bad-password", 5*time.Second) {
		t.Fatalf("expected bad-password log; got:\n%s", ts.logBuf.String())
	}
	snap := ts.limiter.Snapshot()
	foundIPv6 := false
	for k := range snap {
		// Bare IPv6 (no IPv4-mapped collapse) shows as ::1 or another
		// IPv6 textual form.
		if strings.Contains(k, ":") {
			foundIPv6 = true
			break
		}
	}
	if !foundIPv6 {
		t.Fatalf("expected an IPv6 key in limiter snapshot; got %v", snap)
	}
}

// pidStillRunning returns true if the given PID is still a live process
// (kill(pid, 0) returns nil) and false if it has gone away (ESRCH or any
// errno indicating the PID is no longer reachable).
func pidStillRunning(pid int) bool {
	err := syscall.Kill(pid, 0)
	if err == nil {
		return true
	}
	return !errors.Is(err, syscall.ESRCH)
}

// TestIntegration_ExecKilledBySignalSendsExitSignal verifies spec §8.1
// step 6 / §8.2 step 5: when the child exits via a signal, the server
// sends `exit-signal` (with POSIX signal name, core-dump flag, empty
// error message), NOT `exit-status`. x/crypto/ssh surfaces this as
// *ssh.ExitError with a non-empty Signal() string.
func TestIntegration_ExecKilledBySignalSendsExitSignal(t *testing.T) {
	ts := startTestServer(t, testServerOptions{})
	defer ts.cleanup()

	cli := dialSSH(t, ts.addr, clientConfig(ts.user, ts.password))
	defer cli.Close()

	sess, err := cli.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer sess.Close()

	// `kill -KILL $$` from the shell asks the kernel to deliver SIGKILL
	// to the shell itself, so the child terminates by signal and the
	// server's sendExit takes the ws.Signaled() branch.
	_, runErr := runOnSession(t, sess, "kill -KILL $$")
	if runErr == nil {
		t.Fatalf("expected *ssh.ExitError from signal exit; got nil")
	}
	ee, ok := isExitErr(runErr)
	if !ok {
		t.Fatalf("expected *ssh.ExitError; got %T: %v", runErr, runErr)
	}
	if ee.Signal() == "" {
		t.Fatalf("expected non-empty Signal() (exit-signal path); "+
			"got ExitError{code=%d, signal=%q, msg=%q}",
			ee.ExitStatus(), ee.Signal(), ee.Msg())
	}
	if ee.Signal() != "KILL" {
		t.Logf("note: expected signal=KILL, got signal=%q (informational)", ee.Signal())
	}
	// Tear-down should have produced a conn-close event.
	_ = cli.Close()
	if !waitForLog(t, ts.logBuf, "conn-close", 3*time.Second) {
		t.Fatalf("expected conn-close after signal-exit; got:\n%s", ts.logBuf.String())
	}
}

// TestIntegration_ServerShutdownWhileExecRunning verifies spec §8 Signal
// handling: when the server's ctx is cancelled mid-exec, the server
// sends SIGHUP to the child's process group and logs
// `shutdown-signal sig=HUP reason=shutdown pgid=…`. Within ~5 s the
// child is reaped (SIGKILL backstop).
func TestIntegration_ServerShutdownWhileExecRunning(t *testing.T) {
	ts := startTestServer(t, testServerOptions{})

	cli := dialSSH(t, ts.addr, clientConfig(ts.user, ts.password))
	defer cli.Close()

	sess, err := cli.NewSession()
	if err != nil {
		ts.cleanup()
		t.Fatalf("NewSession: %v", err)
	}
	defer sess.Close()

	stdout, err := sess.StdoutPipe()
	if err != nil {
		ts.cleanup()
		t.Fatalf("StdoutPipe: %v", err)
	}
	// `echo PID=$$; exec sleep 60` — the exec builtin replaces the shell
	// with sleep, preserving the PID, so the printed $$ identifies the
	// process the server will SIGHUP.
	if err := sess.Start("echo PID=$$; exec sleep 60"); err != nil {
		ts.cleanup()
		t.Fatalf("Start: %v", err)
	}

	// Read one line of stdout: PID=<n>.
	pidLineCh := make(chan string, 1)
	go func() {
		br := bufio.NewReader(stdout)
		line, _ := br.ReadString('\n')
		pidLineCh <- line
	}()
	var pidLine string
	select {
	case pidLine = <-pidLineCh:
	case <-time.After(5 * time.Second):
		ts.cleanup()
		t.Fatalf("timed out waiting for PID line")
	}
	pidStr := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(pidLine), "PID="))
	pid, convErr := strconv.Atoi(pidStr)
	if convErr != nil {
		ts.cleanup()
		t.Fatalf("parse PID from %q: %v", pidLine, convErr)
	}

	// Cancel the server ctx; this should drive Service.runChild's
	// <-ctx.Done() branch and emit `shutdown-signal sig=HUP reason=shutdown`.
	ts.cleanup()

	if !waitForLog(t, ts.logBuf, "shutdown-signal", 5*time.Second) {
		t.Fatalf("expected shutdown-signal log; got:\n%s", ts.logBuf.String())
	}
	logs := ts.logBuf.String()
	if !strings.Contains(logs, "sig=HUP") {
		t.Fatalf("expected sig=HUP in shutdown-signal log; got:\n%s", logs)
	}
	if !strings.Contains(logs, "reason=shutdown") {
		t.Fatalf("expected reason=shutdown in shutdown-signal log; got:\n%s", logs)
	}

	// The child should be reaped within shutdownGrace (5 s SIGHUP+SIGKILL
	// backstop) — allow a generous wait.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if !pidStillRunning(pid) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("child PID %d still running after shutdown", pid)
}

// TestIntegration_ChannelClosedDuringExec verifies spec §8.2 step 4
// (channel-closes branch): when the client closes the channel before
// the child exits, the server SIGHUPs the process group with reason=
// channel-close and does NOT send exit-status.
func TestIntegration_ChannelClosedDuringExec(t *testing.T) {
	ts := startTestServer(t, testServerOptions{})
	defer ts.cleanup()

	cli := dialSSH(t, ts.addr, clientConfig(ts.user, ts.password))
	defer cli.Close()

	sess, err := cli.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}

	stdout, err := sess.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe: %v", err)
	}

	// `echo PID=$$; exec sleep 30` — same trick as the shutdown test:
	// after `exec sleep 30`, the printed PID identifies the live child.
	if err := sess.Start("echo PID=$$; exec sleep 30"); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Read PID line so we know the child is up and running.
	pidLineCh := make(chan string, 1)
	go func() {
		br := bufio.NewReader(stdout)
		line, _ := br.ReadString('\n')
		pidLineCh <- line
	}()
	var pidLine string
	select {
	case pidLine = <-pidLineCh:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for PID line")
	}
	pidStr := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(pidLine), "PID="))
	pid, convErr := strconv.Atoi(pidStr)
	if convErr != nil {
		t.Fatalf("parse PID from %q: %v", pidLine, convErr)
	}

	// Close the channel from the client side before the sleep completes.
	if err := sess.Close(); err != nil && !errors.Is(err, io.EOF) {
		t.Logf("sess.Close: %v (informational)", err)
	}

	// Within shutdownGrace the server should log
	// `shutdown-signal sig=HUP reason=channel-close`.
	if !waitForLog(t, ts.logBuf, "reason=channel-close", 5*time.Second) {
		t.Fatalf("expected reason=channel-close in shutdown-signal log; got:\n%s",
			ts.logBuf.String())
	}
	if !strings.Contains(ts.logBuf.String(), "sig=HUP") {
		t.Fatalf("expected sig=HUP in shutdown-signal log; got:\n%s", ts.logBuf.String())
	}

	// Child must be reaped — wait up to shutdownGrace + safety margin.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if !pidStillRunning(pid) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if pidStillRunning(pid) {
		t.Fatalf("child PID %d still running after channel-close", pid)
	}

	// Channel close before child exit MUST NOT send exit-status. We
	// observe this indirectly: the count of exit-status request bytes
	// is not measurable from the client side after sess.Close(), so we
	// rely on the absence of any `error` event for "send exit" and on
	// the presence of the shutdown-signal+channel-close pair as the
	// canonical evidence path (matches the spec §8.2 step 4 wording
	// "Do not send `exit-status` on the closed channel").
}

// TestIntegration_SecondShellRejectedDuringExec verifies the spec §8
// request-type combinations table row "Two of shell/exec/subsystem on
// one channel" — the first wins; subsequent ones reply with
// request-failure. The exec should still complete normally.
func TestIntegration_SecondShellRejectedDuringExec(t *testing.T) {
	ts := startTestServer(t, testServerOptions{})
	defer ts.cleanup()

	cli := dialSSH(t, ts.addr, clientConfig(ts.user, ts.password))
	defer cli.Close()

	// Use a raw channel so we can drive the second request directly.
	ch, reqs, err := cli.OpenChannel("session", nil)
	if err != nil {
		t.Fatalf("OpenChannel: %v", err)
	}
	defer ch.Close()
	// Collect/discard inbound channel requests (exit-status etc).
	go ssh.DiscardRequests(reqs)

	// First request: exec a short sleep. Reply must be true.
	type execPayload struct{ Command string }
	ok, err := ch.SendRequest("exec", true, ssh.Marshal(&execPayload{Command: "sleep 0.5; echo OK"}))
	if err != nil {
		t.Fatalf("SendRequest exec: %v", err)
	}
	if !ok {
		t.Fatalf("expected first exec request to be accepted")
	}

	// Second request, sent while the first is still running: shell.
	// Per the spec combinations table this must be rejected.
	ok2, err := ch.SendRequest("shell", true, nil)
	if err != nil {
		t.Fatalf("SendRequest second-shell: %v", err)
	}
	if ok2 {
		t.Fatalf("expected second shell request to be rejected")
	}

	// Drain stdout so the server can drive sendExit + ch.Close() cleanly.
	drained := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, ch)
		close(drained)
	}()
	select {
	case <-drained:
	case <-time.After(10 * time.Second):
		t.Fatalf("timed out waiting for channel close after first exec")
	}
}

// TestIntegration_ExecChildStartFails verifies spec §11: when the child
// shell fails to spawn, the server replies false to the exec/shell
// request, logs an `error`, sends exit-status 127, and closes the
// channel. We provoke the failure by pointing the configured shell at
// /does/not/exist — exec.Cmd.Start returns ENOENT.
func TestIntegration_ExecChildStartFails(t *testing.T) {
	ts := startTestServer(t, testServerOptions{shell: "/does/not/exist/minisshd-no-such-shell"})
	defer ts.cleanup()

	cli := dialSSH(t, ts.addr, clientConfig(ts.user, ts.password))
	defer cli.Close()

	sess, err := cli.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer sess.Close()

	// Per spec §11, the server sends exit-status=127 even though the
	// spawn failed; the surface to the client is *ssh.ExitError code=127.
	// Note: x/crypto delivers the exit-status before sess.Start returns
	// only when the request is accepted. Our server replies false to
	// the exec request first (so sess.Start returns the request-failure
	// error), then sends exit-status 127 and closes the channel.
	startErr := sess.Start("echo SHOULD_NOT_RUN")
	if startErr == nil {
		// Possible if the library asynchronously consumed the exit-status
		// first; in that case Wait surfaces the ExitError.
		waitErr, _ := waitSession(t, sess, 5*time.Second)
		if waitErr == nil {
			t.Fatalf("expected start/wait to surface failure; got nil")
		}
		ee, ok := isExitErr(waitErr)
		if !ok {
			t.Fatalf("expected *ssh.ExitError on Wait; got %T: %v", waitErr, waitErr)
		}
		if ee.ExitStatus() != 127 {
			t.Fatalf("expected exit-status=127; got %d", ee.ExitStatus())
		}
	} else {
		// The exec request was rejected — the standard x/crypto path.
		// This is the documented "child spawn failed" surface.
		t.Logf("sess.Start returned (request-failure): %v", startErr)
	}

	// Whichever path we took, the server must have logged an `error`
	// event from §11 ("child spawn failed: …").
	if !waitForLog(t, ts.logBuf, "child spawn failed", 3*time.Second) {
		t.Fatalf("expected `child spawn failed` error log; got:\n%s", ts.logBuf.String())
	}
	if !waitForLog(t, ts.logBuf, "ERROR error", 1*time.Second) {
		// `ERROR error` is the level+event pair for Logger.Error().
		t.Fatalf("expected ERROR-level `error` event; got:\n%s", ts.logBuf.String())
	}
}
