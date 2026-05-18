//go:build e2e

package e2e

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// spawnedServer is the handle returned by spawnServer. The caller is
// expected to defer .stop() in every test to ensure SIGTERM-then-SIGKILL
// teardown per §13.4 harness rule #6.
type spawnedServer struct {
	addr     string
	password string
	user     string
	home     string
	logPath  string
	cmd      *exec.Cmd
	stop     func()
}

// spawnOptions parameterizes spawnServer for the cases that vary user,
// password, or bind. The zero value uses testuser / "testpass" / 127.0.0.1.
type spawnOptions struct {
	user            string
	password        string
	autoGenPassword bool   // omit --pass, --user; parse banner instead
	bind            string // "" -> 127.0.0.1
	shell           string // "" -> auto-discover
	hostKeyPath     string // "" -> default in HOME
	home            string // "" -> t.TempDir()
	extraArgs       []string
	extraEnv        []string // KEY=VALUE
	expectExit      int      // when > 0, spawn-and-wait, returns nil + err
}

var listeningRe = regexp.MustCompile(`port=(\d+)`)
var passwordBannerRe = regexp.MustCompile(`^Password:\s+(\d{6})\s*$`)

// spawnServer launches the compiled binary on an ephemeral port and
// returns once the `listening` event is observed on stdout. Each test
// gets its own HOME and log file.
//
// The teardown sends SIGTERM and waits up to 5 s for graceful exit; if
// the process is still alive after that, it sends SIGKILL and t.Errorf's
// (coverage data is lost on SIGKILL per §13.4 #5).
func spawnServer(t *testing.T, opts spawnOptions) *spawnedServer {
	t.Helper()
	bin := requireBin(t)

	if opts.home == "" {
		opts.home = t.TempDir()
	}
	if opts.bind == "" {
		opts.bind = "127.0.0.1"
	}
	if opts.user == "" {
		opts.user = "testuser"
	}
	if !opts.autoGenPassword {
		if opts.password == "" {
			opts.password = "testpass"
		}
	}
	if opts.shell == "" {
		opts.shell = discoverShellE2E(t)
	}

	args := []string{
		"--port", "0",
		"--bind", opts.bind,
		"--shell", opts.shell,
		"--user", opts.user,
	}
	if !opts.autoGenPassword {
		args = append(args, "--pass", opts.password)
	}
	if opts.hostKeyPath != "" {
		args = append(args, "--host-key", opts.hostKeyPath)
	}
	args = append(args, opts.extraArgs...)

	cmd := exec.Command(bin, args...)
	logPath := filepath.Join(opts.home, "minissh.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatalf("create log file: %v", err)
	}

	// Tee stdout via a pipe so we can read the listening line + banner
	// while still writing to the log file. Stderr goes straight to the
	// log file.
	stdoutReader, stdoutWriter, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	cmd.Stdout = stdoutWriter
	cmd.Stderr = logFile

	// Build env: minimal HOME / PATH / inherit everything else.
	cmd.Env = []string{
		"HOME=" + opts.home,
		"PATH=" + os.Getenv("PATH"),
		"USER=testuser",
		"LOGNAME=testuser",
		// Each spawned binary writes its coverage data here.
		"GOCOVERDIR=" + coverDir,
	}
	cmd.Env = append(cmd.Env, opts.extraEnv...)

	// Put the child in its own session so we can deliver signals to its
	// process group cleanly. Per §8 the child also setsid for its own
	// children; this is the outer wrapper.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if err := cmd.Start(); err != nil {
		_ = stdoutWriter.Close()
		_ = logFile.Close()
		t.Fatalf("start %s: %v", bin, err)
	}
	// Close the parent's copy of the write end so EOF propagates if the
	// child exits.
	_ = stdoutWriter.Close()

	// Reader goroutine: stream stdout into the log file AND parse the
	// listening / Password lines.
	type startInfo struct {
		port     int
		password string
		err      error
	}
	startCh := make(chan startInfo, 1)
	var tail bytes.Buffer
	_ = tail // populated by the goroutine below
	scanner := bufio.NewScanner(stdoutReader)
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	go func() {
		var port int
		var password string
		var emittedStart bool
		for scanner.Scan() {
			line := scanner.Text()
			_, _ = logFile.WriteString(line + "\n")
			tail.WriteString(line + "\n")
			if !emittedStart {
				if m := passwordBannerRe.FindStringSubmatch(line); m != nil {
					password = m[1]
				}
				if strings.Contains(line, "listening") {
					if m := listeningRe.FindStringSubmatch(line); m != nil {
						p, perr := strconv.Atoi(m[1])
						if perr != nil {
							startCh <- startInfo{err: fmt.Errorf("parse port: %w", perr)}
							emittedStart = true
							continue
						}
						port = p
						if password != "" || !opts.autoGenPassword {
							startCh <- startInfo{port: port, password: password}
							emittedStart = true
						}
					}
				} else if emittedStart == false && opts.autoGenPassword && password != "" && port != 0 {
					startCh <- startInfo{port: port, password: password}
					emittedStart = true
				}
			}
		}
	}()

	// Wait for the listening line, with a 10 s deadline.
	info := startInfo{}
	select {
	case info = <-startCh:
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		t.Fatalf("did not see listening line within 10 s; log tail:\n%s", tail.String())
	}
	if info.err != nil {
		_ = cmd.Process.Kill()
		t.Fatalf("parse startup: %v", info.err)
	}

	pw := opts.password
	if opts.autoGenPassword {
		pw = info.password
		if pw == "" {
			_ = cmd.Process.Kill()
			t.Fatalf("auto-generated password not seen in stdout; tail:\n%s", tail.String())
		}
	}

	addr := fmt.Sprintf("%s:%d", opts.bind, info.port)
	if opts.bind == "::" {
		addr = fmt.Sprintf("[::1]:%d", info.port)
	}

	srv := &spawnedServer{
		addr:     addr,
		password: pw,
		user:     opts.user,
		home:     opts.home,
		logPath:  logPath,
		cmd:      cmd,
	}

	var stopOnce sync.Once
	srv.stop = func() {
		stopOnce.Do(func() {
			if cmd.Process == nil {
				return
			}
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
				<-done
				t.Errorf("server did not exit within 5 s of SIGTERM; SIGKILL used (coverage data lost for this test)")
			}
			_ = logFile.Close()
			_ = stdoutReader.Close()
		})
	}
	return srv
}

// readLog reads the entire current log file content for assertions.
func (s *spawnedServer) readLog(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(s.logPath)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	return string(data)
}

// awaitLogContains polls the log file until substr appears or the
// timeout elapses.
func (s *spawnedServer) awaitLogContains(t *testing.T, substr string, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if strings.Contains(s.readLog(t), substr) {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

// discoverShellE2E mirrors the shell discovery used by the §13.3 helper.
// On Linux dev hosts /bin/zsh is usually absent; fall back to bash / sh.
func discoverShellE2E(t *testing.T) string {
	t.Helper()
	for _, p := range []string{"/bin/zsh", "/bin/bash", "/bin/sh"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	t.Skip("no usable shell (/bin/zsh, /bin/bash, /bin/sh) found")
	return ""
}

// runMinisshOnce spawns the binary expecting it to exit non-zero
// (e.g. invalid bind). Returns exit code and combined stdout/stderr.
func runMinisshOnce(t *testing.T, opts spawnOptions) (int, string) {
	t.Helper()
	bin := requireBin(t)
	if opts.shell == "" {
		opts.shell = discoverShellE2E(t)
	}
	if opts.home == "" {
		opts.home = t.TempDir()
	}
	args := []string{"--port", "0", "--shell", opts.shell}
	if opts.bind != "" {
		args = append(args, "--bind", opts.bind)
	}
	if opts.user != "" {
		args = append(args, "--user", opts.user)
	}
	if opts.password != "" {
		args = append(args, "--pass", opts.password)
	}
	if opts.hostKeyPath != "" {
		args = append(args, "--host-key", opts.hostKeyPath)
	}
	args = append(args, opts.extraArgs...)

	cmd := exec.Command(bin, args...)
	cmd.Env = []string{
		"HOME=" + opts.home,
		"PATH=" + os.Getenv("PATH"),
		"GOCOVERDIR=" + coverDir,
	}
	cmd.Env = append(cmd.Env, opts.extraEnv...)

	out, err := cmd.CombinedOutput()
	code := 0
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
		} else {
			code = -1
		}
	}
	return code, string(out)
}

// pidStillRunning returns true if the PID is still alive (kill -0).
func pidStillRunning(pid int) bool {
	err := syscall.Kill(pid, 0)
	if err == nil {
		return true
	}
	return !errors.Is(err, syscall.ESRCH)
}

// nonLoopbackIPv4 returns the first non-loopback IPv4 address on the
// host, or empty if none exists. Used by the bind-to-loopback test.
func nonLoopbackIPv4() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		ip, _, err := net.ParseCIDR(a.String())
		if err != nil {
			continue
		}
		if ip.To4() != nil && !ip.IsLoopback() {
			return ip.String()
		}
	}
	return ""
}

// awaitPort polls the given addr until a TCP DialTimeout succeeds or
// the deadline expires.
func awaitPort(addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("timeout dialing %s", addr)
}

// Force a small subset of stdlib symbols through indirection helpers so
// the import list of this file stays narrow.
var (
	_ = io.EOF
	_ = filepath.Join
)
