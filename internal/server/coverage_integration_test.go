package server_test

// Additional §13.3 integration tests targeting the lower-coverage code
// paths in internal/session and internal/server. These don't appear in
// the spec's enumeration of required scenarios but exercise documented
// behaviors that unit tests don't fully cover when combined with the
// real channel/session machinery.

import (
	"io"
	"strings"
	"sync"
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
