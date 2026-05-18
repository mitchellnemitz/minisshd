//go:build e2e

package e2e

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/creack/pty"
)

// sshOpts is the universal slice of -o flags every §13.4 invocation
// must pass to avoid host-key prompts and noisy output. Tests that need
// a real known-hosts file (test 13) override individually.
func sshOpts() []string {
	return []string{
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "GlobalKnownHostsFile=/dev/null",
		"-o", "LogLevel=ERROR",
	}
}

// passwordPromptRe matches the OpenSSH password prompt — ".*password:"
// at the end of the buffered output (case-insensitive).
var passwordPromptRe = regexp.MustCompile(`(?i)password:\s*$`)

// ptyResult holds the outcome of a PTY-driven ssh/sftp/scp invocation.
type ptyResult struct {
	output   string
	err      error
	exitCode int
	signaled bool
}

// runSSHCommand spawns one of /usr/bin/{ssh,sftp,scp} under a PTY,
// supplies the password when the prompt appears, then writes followup
// lines (if any) and reads remaining output until EOF or timeout.
//
// For non-interactive uses (e.g. `ssh host 'cmd'`), pass nil for
// followups; the helper just collects output after the password.
func runSSHCommand(
	t *testing.T,
	args []string,
	password string,
	followups []string,
	timeout time.Duration,
) ptyResult {
	t.Helper()
	cmd := exec.Command(args[0], args[1:]...)
	ptmx, err := pty.Start(cmd)
	if err != nil {
		t.Fatalf("pty.Start %s: %v", joinArgs(args), err)
	}

	var buf safeBuffer
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = io.Copy(&buf, ptmx)
	}()

	// Wait for the password prompt (or for the process to exit without
	// prompting, which means an early failure we can still surface).
	deadline := time.Now().Add(10 * time.Second)
	gotPrompt := false
	for time.Now().Before(deadline) {
		s := buf.String()
		if passwordPromptRe.MatchString(s) {
			gotPrompt = true
			break
		}
		// If the child exited before prompting (e.g. connect refused)
		// break out of the wait loop and let the outer collection
		// finish.
		if !pidRunning(cmd.Process.Pid) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if gotPrompt {
		if _, err := io.WriteString(ptmx, password+"\n"); err != nil {
			t.Logf("write password: %v", err)
		}
		// Drain the echoed password line + any pre-banner output.
		time.Sleep(100 * time.Millisecond)
	}
	for _, line := range followups {
		_, _ = io.WriteString(ptmx, line)
	}

	// Wait for completion with overall timeout.
	waitCh := make(chan error, 1)
	go func() { waitCh <- cmd.Wait() }()
	res := ptyResult{}
	select {
	case res.err = <-waitCh:
	case <-time.After(timeout):
		_ = cmd.Process.Kill()
		<-waitCh
		res.err = fmt.Errorf("timeout %s waiting for %s", timeout, joinArgs(args))
	}
	// Give the reader goroutine a beat to drain pty's buffer.
	_ = ptmx.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
	}

	res.output = buf.String()
	if res.err != nil {
		var ee *exec.ExitError
		if errors.As(res.err, &ee) {
			res.exitCode = ee.ExitCode()
			if ws, ok := ee.Sys().(syscall.WaitStatus); ok {
				res.signaled = ws.Signaled()
			}
		} else {
			res.exitCode = -1
		}
	}
	return res
}

// safeBuffer is a thread-safe *bytes.Buffer used by the PTY copy
// goroutine and the reader spinwait.
type safeBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *safeBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *safeBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// pidRunning is the e2e-local equivalent of pidStillRunning in spawn_test.go.
// We keep both to avoid coupling the unit-test util to PTY code.
func pidRunning(pid int) bool {
	err := syscall.Kill(pid, 0)
	if err == nil {
		return true
	}
	return !errors.Is(err, syscall.ESRCH)
}

// startPTY is a thin wrapper around pty.Start that returns the PTY
// master file so the caller can drive stdin/stdout manually. The
// dedicated -N port-forwarding test and graceful-shutdown test need
// this lower-level access.
func startPTY(cmd *exec.Cmd) (*os.File, error) {
	return pty.Start(cmd)
}

// drainPTYAndFeedPassword reads from ptmx; when it sees the password
// prompt it writes the password+newline once; then keeps draining.
// Intended for the -N ssh-forwarding case where we don't care about
// stdout but must answer the password prompt and prevent pipe backup.
func drainPTYAndFeedPassword(ptmx *os.File, password string) {
	fed := false
	buf := make([]byte, 4096)
	var acc bytes.Buffer
	for {
		n, err := ptmx.Read(buf)
		if n > 0 {
			acc.Write(buf[:n])
			if !fed && passwordPromptRe.MatchString(acc.String()) {
				_, _ = ptmx.Write([]byte(password + "\n"))
				fed = true
			}
		}
		if err != nil {
			return
		}
	}
}
