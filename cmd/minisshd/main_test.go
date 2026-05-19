package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// syncBuffer wraps a bytes.Buffer with a mutex so concurrent writes from
// run()'s logger and reads from the test goroutine don't race.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// unsetenv temporarily clears an env var for the duration of the test,
// distinct from t.Setenv("X","") which leaves the variable set-but-empty.
// auth.ResolvePasswordStrict cares about the distinction.
func unsetenv(t *testing.T, key string) {
	t.Helper()
	orig, ok := os.LookupEnv(key)
	if err := os.Unsetenv(key); err != nil {
		t.Fatalf("unsetenv %s: %v", key, err)
	}
	t.Cleanup(func() {
		if ok {
			_ = os.Setenv(key, orig)
		} else {
			_ = os.Unsetenv(key)
		}
	})
}

// isolateHome points $HOME at a fresh tempdir and clears MINISSHD_PASS /
// MINISSHD_USER so tests don't pick up the host environment. Returns the
// new HOME path. The default --host-key lives at $HOME/.minisshd/host_key
// after this runs.
func isolateHome(t *testing.T) string {
	t.Helper()
	h := t.TempDir()
	t.Setenv("HOME", h)
	unsetenv(t, "MINISSHD_PASS")
	unsetenv(t, "MINISSHD_USER")
	unsetenv(t, "MINISSHD_LOG_FORMAT")
	unsetenv(t, "MINISSHD_AUTH")
	unsetenv(t, "MINISSHD_AUTHORIZED_KEYS")
	return h
}

// defaultGoodArgs returns flag args that pass every §2 step 1-7 validation
// when combined with an isolated HOME and a free ephemeral port (--port 0).
// Tests override individual flags to exercise specific failure cases.
func defaultGoodArgs() []string {
	return []string{
		"--port", "0",
		"--bind", "127.0.0.1",
		"--pass", "hunter2",
		"--user", "testuser",
		"--shell", "/bin/sh",
	}
}

// runUntilListening invokes run() in a goroutine, waits up to 3 s for the
// `listening` event to appear in stdout, then cancels the context and
// returns the captured stdout, stderr, and exit code.
func runUntilListening(t *testing.T, args []string) (stdoutStr, stderrStr string, rc int) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	stdout := &syncBuffer{}
	stderr := &syncBuffer{}
	done := make(chan int, 1)
	go func() {
		done <- run(ctx, args, stdout, stderr)
	}()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(stdout.String(), " listening ") {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()

	select {
	case rc = <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("run() did not return within 5 s after cancel; stdout=%q stderr=%q",
			stdout.String(), stderr.String())
	}
	return stdout.String(), stderr.String(), rc
}

// runToCompletion calls run() with a non-cancellable context and waits for
// it to return on its own. Used for failure-path tests where run() exits
// without ever reaching the ctx.Done() block.
func runToCompletion(t *testing.T, args []string) (stdoutStr, stderrStr string, rc int) {
	t.Helper()
	stdout := &syncBuffer{}
	stderr := &syncBuffer{}
	done := make(chan int, 1)
	go func() {
		done <- run(context.Background(), args, stdout, stderr)
	}()
	select {
	case rc = <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("run() did not return; stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	return stdout.String(), stderr.String(), rc
}

func TestRun_PortOutOfRange_Negative(t *testing.T) {
	isolateHome(t)
	args := append([]string{}, defaultGoodArgs()...)
	args[1] = "-1"
	_, stderr, rc := runToCompletion(t, args)
	if rc != exitBadConfig {
		t.Fatalf("rc=%d want %d; stderr=%q", rc, exitBadConfig, stderr)
	}
	if !strings.Contains(stderr, "-1") {
		t.Errorf("stderr should name the rejected value -1; got %q", stderr)
	}
}

func TestRun_PortOutOfRange_TooLarge(t *testing.T) {
	isolateHome(t)
	args := append([]string{}, defaultGoodArgs()...)
	args[1] = "65536"
	_, stderr, rc := runToCompletion(t, args)
	if rc != exitBadConfig {
		t.Fatalf("rc=%d want %d", rc, exitBadConfig)
	}
	if !strings.Contains(stderr, "65536") {
		t.Errorf("stderr should name 65536; got %q", stderr)
	}
}

func TestRun_PortNonNumeric(t *testing.T) {
	isolateHome(t)
	args := append([]string{}, defaultGoodArgs()...)
	args[1] = "abc"
	_, stderr, rc := runToCompletion(t, args)
	if rc != exitBadConfig {
		t.Fatalf("rc=%d want %d", rc, exitBadConfig)
	}
	if !strings.Contains(stderr, "abc") {
		t.Errorf("stderr should name the rejected value; got %q", stderr)
	}
}

func TestRun_PortZeroBindsAndReportsActualPort(t *testing.T) {
	isolateHome(t)
	stdout, stderr, rc := runUntilListening(t, defaultGoodArgs())
	if rc != exitOK {
		t.Fatalf("rc=%d want %d; stderr=%q", rc, exitOK, stderr)
	}
	re := regexp.MustCompile(`port=(\d+)`)
	m := re.FindStringSubmatch(stdout)
	if m == nil {
		t.Fatalf("listening event should report port=<n>; stdout=%q", stdout)
	}
	if m[1] == "0" {
		t.Errorf("listening event should report the actual bound port, not 0; stdout=%q", stdout)
	}
}

func TestRun_ShellNonexistent(t *testing.T) {
	isolateHome(t)
	args := append([]string{}, defaultGoodArgs()...)
	// Replace --shell value.
	for i, a := range args {
		if a == "--shell" {
			args[i+1] = "/nonexistent/binary"
			break
		}
	}
	_, stderr, rc := runToCompletion(t, args)
	if rc != exitBadConfig {
		t.Fatalf("rc=%d want %d; stderr=%q", rc, exitBadConfig, stderr)
	}
	if !strings.Contains(stderr, "/nonexistent/binary") {
		t.Errorf("stderr should name the rejected --shell value; got %q", stderr)
	}
}

func TestRun_ShellIsDirectory(t *testing.T) {
	isolateHome(t)
	args := append([]string{}, defaultGoodArgs()...)
	for i, a := range args {
		if a == "--shell" {
			args[i+1] = "/etc"
			break
		}
	}
	_, stderr, rc := runToCompletion(t, args)
	if rc != exitBadConfig {
		t.Fatalf("rc=%d want %d", rc, exitBadConfig)
	}
	if !strings.Contains(stderr, "regular file") && !strings.Contains(stderr, "executable") {
		t.Errorf("stderr should explain why /etc is not a valid shell; got %q", stderr)
	}
}

func TestRun_ShellNotExecutable(t *testing.T) {
	isolateHome(t)
	// /etc/passwd is a regular file but not executable.
	args := append([]string{}, defaultGoodArgs()...)
	for i, a := range args {
		if a == "--shell" {
			args[i+1] = "/etc/passwd"
			break
		}
	}
	_, stderr, rc := runToCompletion(t, args)
	if rc != exitBadConfig {
		t.Fatalf("rc=%d want %d", rc, exitBadConfig)
	}
	if !strings.Contains(stderr, "/etc/passwd") {
		t.Errorf("stderr should name the rejected --shell; got %q", stderr)
	}
}

func TestRun_BindInvalidIPLiteral(t *testing.T) {
	isolateHome(t)
	args := append([]string{}, defaultGoodArgs()...)
	for i, a := range args {
		if a == "--bind" {
			args[i+1] = "not-an-ip"
			break
		}
	}
	_, stderr, rc := runToCompletion(t, args)
	if rc != exitBadConfig {
		t.Fatalf("rc=%d want %d", rc, exitBadConfig)
	}
	if !strings.Contains(stderr, "not-an-ip") {
		t.Errorf("stderr should name the rejected --bind; got %q", stderr)
	}
}

func TestRun_BindOutOfRangeIPv4(t *testing.T) {
	isolateHome(t)
	args := append([]string{}, defaultGoodArgs()...)
	for i, a := range args {
		if a == "--bind" {
			args[i+1] = "999.0.0.1"
			break
		}
	}
	_, _, rc := runToCompletion(t, args)
	if rc != exitBadConfig {
		t.Fatalf("rc=%d want %d", rc, exitBadConfig)
	}
}

// ipv6Available probes the local kernel for IPv6 support. CI runners or
// minimal Linux containers sometimes ship without it, in which case the
// ::1 bind test is meaningless and skipped.
func ipv6Available() bool {
	l, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		return false
	}
	_ = l.Close()
	return true
}

func TestRun_BindIPv6LoopbackOK(t *testing.T) {
	if !ipv6Available() {
		t.Skip("IPv6 not available on this host")
	}
	isolateHome(t)
	args := append([]string{}, defaultGoodArgs()...)
	for i, a := range args {
		if a == "--bind" {
			args[i+1] = "::1"
			break
		}
	}
	stdout, stderr, rc := runUntilListening(t, args)
	if rc != exitOK {
		t.Fatalf("rc=%d want %d; stderr=%q", rc, exitOK, stderr)
	}
	if !strings.Contains(stdout, "bind=::1") {
		t.Errorf("stdout should record bind=::1; got %q", stdout)
	}
}

func TestRun_MinisshdDirTooOpen(t *testing.T) {
	home := isolateHome(t)
	dir := filepath.Join(home, ".minisshd")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Defensive: MkdirAll respects umask, so chmod explicitly.
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	_, stderr, rc := runToCompletion(t, defaultGoodArgs())
	if rc != exitFSFailure {
		t.Fatalf("rc=%d want %d; stderr=%q", rc, exitFSFailure, stderr)
	}
	if !strings.Contains(stderr, "chmod 700") {
		t.Errorf("stderr should instruct chmod 700; got %q", stderr)
	}
}

func TestRun_MinisshdDirCorrectModeAccepted(t *testing.T) {
	home := isolateHome(t)
	dir := filepath.Join(home, ".minisshd")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, rc := runUntilListening(t, defaultGoodArgs())
	if rc != exitOK {
		t.Fatalf("rc=%d want %d; stderr=%q stdout=%q", rc, exitOK, stderr, stdout)
	}
	// Verify the directory mode wasn't widened.
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Errorf("directory mode changed to %#o; expected 0700", info.Mode().Perm())
	}
}

func TestRun_BannerSuppressedWithFlagPass(t *testing.T) {
	isolateHome(t)
	stdout, stderr, rc := runUntilListening(t, defaultGoodArgs())
	if rc != exitOK {
		t.Fatalf("rc=%d want %d; stderr=%q", rc, exitOK, stderr)
	}
	if strings.Contains(stdout, "Password:") {
		t.Errorf("stdout should not contain a Password: banner when --pass is set; got %q", stdout)
	}
}

func TestRun_BannerSuppressedWithEnvPass(t *testing.T) {
	isolateHome(t)
	t.Setenv("MINISSHD_PASS", "from-env")
	// Remove --pass from args.
	args := []string{
		"--port", "0",
		"--bind", "127.0.0.1",
		"--user", "testuser",
		"--shell", "/bin/sh",
	}
	stdout, stderr, rc := runUntilListening(t, args)
	if rc != exitOK {
		t.Fatalf("rc=%d want %d; stderr=%q", rc, exitOK, stderr)
	}
	if strings.Contains(stdout, "Password:") {
		t.Errorf("stdout should not contain a Password: banner when MINISSHD_PASS is set; got %q", stdout)
	}
}

func TestRun_BannerEmittedWhenNoPasswordConfigured(t *testing.T) {
	isolateHome(t)
	args := []string{
		"--port", "0",
		"--bind", "127.0.0.1",
		"--user", "testuser",
		"--shell", "/bin/sh",
	}
	stdout, stderr, rc := runUntilListening(t, args)
	if rc != exitOK {
		t.Fatalf("rc=%d want %d; stderr=%q", rc, exitOK, stderr)
	}
	// Spec §13.2: exactly one ^Password: \d{6}$ line.
	re := regexp.MustCompile(`(?m)^Password: \d{6}$`)
	matches := re.FindAllString(stdout, -1)
	if len(matches) != 1 {
		t.Fatalf("expected exactly one Password: <6digits> line; got %d matches in %q", len(matches), stdout)
	}
	// The banner must precede the listening event (banner is printed
	// only after the listener has bound, but it's printed BEFORE the
	// listening log line per the §2 order).
	bannerIdx := strings.Index(stdout, "Password: ")
	listeningIdx := strings.Index(stdout, " listening ")
	if bannerIdx < 0 || listeningIdx < 0 || bannerIdx >= listeningIdx {
		t.Errorf("banner should appear before listening event; stdout=%q", stdout)
	}
}

func TestRun_BannerSuppressedOnPreBindFailure(t *testing.T) {
	isolateHome(t)
	// Bad bind ensures step 7 fails before step 8 (banner). With no
	// password configured the auto-generated banner must NOT be emitted
	// — per spec §2 step 8 the password isn't even generated.
	args := []string{
		"--port", "0",
		"--bind", "999.999.999.999",
		"--user", "testuser",
		"--shell", "/bin/sh",
	}
	stdout, _, rc := runToCompletion(t, args)
	if rc == exitOK {
		t.Fatalf("rc=%d; expected non-zero on bad bind", rc)
	}
	if stdout != "" {
		t.Errorf("stdout should be empty on pre-bind failure; got %q", stdout)
	}
}

func TestRun_EmptyPassFlagRejected(t *testing.T) {
	isolateHome(t)
	args := []string{
		"--port", "0",
		"--bind", "127.0.0.1",
		"--user", "testuser",
		"--shell", "/bin/sh",
		"--pass", "",
	}
	_, stderr, rc := runToCompletion(t, args)
	if rc != exitBadConfig {
		t.Fatalf("rc=%d want %d; stderr=%q", rc, exitBadConfig, stderr)
	}
	if !strings.Contains(strings.ToLower(stderr), "password") {
		t.Errorf("stderr should mention password; got %q", stderr)
	}
}

func TestRun_HostKeyPersistedAcrossInvocations(t *testing.T) {
	home := isolateHome(t)

	// First invocation generates the key.
	_, _, rc := runUntilListening(t, defaultGoodArgs())
	if rc != exitOK {
		t.Fatalf("first invocation rc=%d want %d", rc, exitOK)
	}
	keyPath := filepath.Join(home, ".minisshd", "host_key")
	first, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}

	// Second invocation should reuse the same key.
	_, _, rc = runUntilListening(t, defaultGoodArgs())
	if rc != exitOK {
		t.Fatalf("second invocation rc=%d want %d", rc, exitOK)
	}
	second, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Error("host key was rotated across invocations; should persist")
	}
}

// TestRun_ValidateShellHelper covers the validateShell helper directly so
// the symlink + regular-file + executable checks have unit coverage
// independent of full run() invocations.
func TestRun_ValidateShellHelper(t *testing.T) {
	tmp := t.TempDir()

	// A regular executable file should pass.
	good := filepath.Join(tmp, "good")
	if err := os.WriteFile(good, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := validateShell(good); err != nil {
		t.Errorf("good shell rejected: %v", err)
	}

	// A non-executable regular file should be rejected.
	notExec := filepath.Join(tmp, "notexec")
	if err := os.WriteFile(notExec, []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := validateShell(notExec); err == nil {
		t.Error("non-executable file should be rejected")
	}

	// A directory should be rejected.
	if err := validateShell(tmp); err == nil {
		t.Error("directory should be rejected")
	}

	// A symlink to a good file should resolve and pass.
	link := filepath.Join(tmp, "link")
	if err := os.Symlink(good, link); err != nil {
		t.Fatal(err)
	}
	if err := validateShell(link); err != nil {
		t.Errorf("good symlink rejected: %v", err)
	}

	// A broken symlink should be rejected.
	broken := filepath.Join(tmp, "broken")
	if err := os.Symlink(filepath.Join(tmp, "nonexistent"), broken); err != nil {
		t.Fatal(err)
	}
	if err := validateShell(broken); err == nil {
		t.Error("broken symlink should be rejected")
	}
}

// TestRun_EnsureMinisshdDirHelper covers ensureMinisshdDir's create-or-check
// behavior in isolation.
func TestRun_EnsureMinisshdDirHelper(t *testing.T) {
	root := t.TempDir()

	// Missing directory: create at 0700.
	d1 := filepath.Join(root, "a")
	if err := ensureMinisshdDir(d1); err != nil {
		t.Fatalf("create missing dir: %v", err)
	}
	info, err := os.Stat(d1)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Errorf("created dir mode = %#o, want 0700", info.Mode().Perm())
	}

	// Pre-existing 0700: accept.
	if err := ensureMinisshdDir(d1); err != nil {
		t.Errorf("accept-existing 0700 dir: %v", err)
	}

	// Pre-existing 0755: reject with chmod 700 message.
	d2 := filepath.Join(root, "b")
	if err := os.MkdirAll(d2, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(d2, 0o755); err != nil {
		t.Fatal(err)
	}
	err = ensureMinisshdDir(d2)
	if err == nil {
		t.Fatal("0755 dir should be rejected")
	}
	if !strings.Contains(err.Error(), "chmod 700") {
		t.Errorf("error should instruct chmod 700; got %v", err)
	}

	// Pre-existing path that is a file: reject.
	d3 := filepath.Join(root, "file")
	if err := os.WriteFile(d3, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ensureMinisshdDir(d3); err == nil {
		t.Error("file-not-dir should be rejected")
	}
}

// TestRun_HostKeyCorruptExits4 exercises the §13.2 hostkey-corruption
// surface — cmd/minisshd maps hostkey.ErrKeyCorrupt to exit code 4.
func TestRun_HostKeyCorruptExits4(t *testing.T) {
	home := isolateHome(t)
	dir := filepath.Join(home, ".minisshd")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "host_key")
	if err := os.WriteFile(keyPath, []byte{0, 1, 2, 3, 4}, 0o600); err != nil {
		t.Fatal(err)
	}
	_, stderr, rc := runToCompletion(t, defaultGoodArgs())
	if rc != exitFSFailure {
		t.Fatalf("rc=%d want %d; stderr=%q", rc, exitFSFailure, stderr)
	}
	if !strings.Contains(stderr, "corrupt") {
		t.Errorf("stderr should mention corrupt; got %q", stderr)
	}
}

// TestRun_HostKeyTooOpenPermissionsExits4 covers the §13.2 "host key
// world-readable" case.
func TestRun_HostKeyTooOpenPermissionsExits4(t *testing.T) {
	home := isolateHome(t)
	dir := filepath.Join(home, ".minisshd")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	// Generate a key first.
	stdout1, _, rc := runUntilListening(t, defaultGoodArgs())
	if rc != exitOK {
		t.Fatalf("first run rc=%d", rc)
	}
	_ = stdout1
	keyPath := filepath.Join(dir, "host_key")
	if err := os.Chmod(keyPath, 0o644); err != nil {
		t.Fatal(err)
	}
	_, stderr, rc := runToCompletion(t, defaultGoodArgs())
	if rc != exitFSFailure {
		t.Fatalf("rc=%d want %d; stderr=%q", rc, exitFSFailure, stderr)
	}
	if !strings.Contains(stderr, "chmod 600") {
		t.Errorf("stderr should instruct chmod 600; got %q", stderr)
	}
}

// Sanity guard against a refactor that breaks the exit-code constants.
func TestRun_ExitCodeConstants(t *testing.T) {
	cases := map[string]int{
		"exitOK":            0,
		"exitInternalError": 1,
		"exitBadConfig":     2,
		"exitBindFailure":   3,
		"exitFSFailure":     4,
	}
	got := map[string]int{
		"exitOK":            exitOK,
		"exitInternalError": exitInternalError,
		"exitBadConfig":     exitBadConfig,
		"exitBindFailure":   exitBindFailure,
		"exitFSFailure":     exitFSFailure,
	}
	for k, v := range cases {
		if got[k] != v {
			t.Errorf("%s = %d, want %d", k, got[k], v)
		}
	}
}

// runUntilListeningJSON is like runUntilListening but waits for the JSON
// sentinel "event":"listening" instead of the logfmt sentinel " listening ".
// Used by tests that start the server with --log-format json.
func runUntilListeningJSON(t *testing.T, args []string) (stdoutStr, stderrStr string, rc int) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	stdout := &syncBuffer{}
	stderr := &syncBuffer{}
	done := make(chan int, 1)
	go func() {
		done <- run(ctx, args, stdout, stderr)
	}()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(stdout.String(), `"event":"listening"`) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()

	select {
	case rc = <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("run() did not return within 5 s after cancel; stdout=%q stderr=%q",
			stdout.String(), stderr.String())
	}
	return stdout.String(), stderr.String(), rc
}

// TestRun_LogFormatUnknownValue asserts that --log-format xml exits 2 and
// mentions the rejected value.
func TestRun_LogFormatUnknownValue(t *testing.T) {
	isolateHome(t)
	args := append([]string{}, defaultGoodArgs()...)
	args = append(args, "--log-format", "xml")
	_, stderr, rc := runToCompletion(t, args)
	if rc != exitBadConfig {
		t.Fatalf("rc=%d want %d; stderr=%q", rc, exitBadConfig, stderr)
	}
	if !strings.Contains(stderr, "minisshd:") {
		t.Errorf("stderr should contain 'minisshd:' prefix; got %q", stderr)
	}
	if !strings.Contains(stderr, "xml") {
		t.Errorf("stderr should name the rejected value 'xml'; got %q", stderr)
	}
}

// TestRun_LogFormatExplicitEmpty asserts that --log-format "" exits 2.
func TestRun_LogFormatExplicitEmpty(t *testing.T) {
	isolateHome(t)
	args := append([]string{}, defaultGoodArgs()...)
	args = append(args, "--log-format", "")
	_, _, rc := runToCompletion(t, args)
	if rc != exitBadConfig {
		t.Fatalf("rc=%d want %d", rc, exitBadConfig)
	}
}

// TestRun_LogFormatEnvIsRespected sets MINISSHD_LOG_FORMAT=json and asserts
// the first log line is valid JSON.
func TestRun_LogFormatEnvIsRespected(t *testing.T) {
	isolateHome(t)
	t.Setenv("MINISSHD_LOG_FORMAT", "json")
	stdout, _, rc := runUntilListeningJSON(t, defaultGoodArgs())
	if rc != exitOK {
		t.Fatalf("rc=%d want %d; stdout=%q", rc, exitOK, stdout)
	}
	// Find a line that contains the listening event.
	for _, line := range strings.Split(stdout, "\n") {
		if strings.Contains(line, `"event":"listening"`) {
			var m map[string]any
			if err := json.Unmarshal([]byte(line), &m); err != nil {
				t.Errorf("listening event is not valid JSON: %q — %v", line, err)
			}
			return
		}
	}
	t.Errorf("no listening event found in JSON output; stdout=%q", stdout)
}

// TestRun_LogFormatFlagWinsOverEnv sets MINISSHD_LOG_FORMAT=json but passes
// --log-format logfmt; asserts the output is logfmt.
func TestRun_LogFormatFlagWinsOverEnv(t *testing.T) {
	isolateHome(t)
	t.Setenv("MINISSHD_LOG_FORMAT", "json")
	args := append([]string{}, defaultGoodArgs()...)
	args = append(args, "--log-format", "logfmt")
	stdout, stderr, rc := runUntilListening(t, args)
	if rc != exitOK {
		t.Fatalf("rc=%d want %d; stderr=%q", rc, exitOK, stderr)
	}
	if !strings.Contains(stdout, " listening ") {
		t.Errorf("expected logfmt listening event; stdout=%q", stdout)
	}
	// Ensure output does not look like JSON.
	if strings.Contains(stdout, `"event":"listening"`) {
		t.Errorf("output should be logfmt, not JSON; stdout=%q", stdout)
	}
}

// TestRun_LogFormatBannerUnaffected starts with --log-format json and no
// --pass and asserts the Password: banner appears before the JSON listening
// event, unaffected by the format flag.
func TestRun_LogFormatBannerUnaffected(t *testing.T) {
	isolateHome(t)
	args := []string{
		"--port", "0",
		"--bind", "127.0.0.1",
		"--user", "testuser",
		"--shell", "/bin/sh",
		"--log-format", "json",
	}
	stdout, stderr, rc := runUntilListeningJSON(t, args)
	if rc != exitOK {
		t.Fatalf("rc=%d want %d; stderr=%q", rc, exitOK, stderr)
	}
	// Banner must appear.
	if !strings.Contains(stdout, "Password: ") {
		t.Errorf("expected Password: banner; stdout=%q", stdout)
	}
	// Banner must precede the listening JSON event.
	bannerIdx := strings.Index(stdout, "Password: ")
	listeningIdx := strings.Index(stdout, `"event":"listening"`)
	if bannerIdx < 0 || listeningIdx < 0 || bannerIdx >= listeningIdx {
		t.Errorf("banner should appear before listening JSON event; stdout=%q", stdout)
	}
	// The listening line must be valid JSON.
	for _, line := range strings.Split(stdout, "\n") {
		if strings.Contains(line, `"event":"listening"`) {
			var m map[string]any
			if err := json.Unmarshal([]byte(line), &m); err != nil {
				t.Errorf("listening line not valid JSON: %q — %v", line, err)
			}
			return
		}
	}
	t.Errorf("no listening JSON event found; stdout=%q", stdout)
}

// TestRun_AuthFlagValidation asserts that invalid --auth values produce exit 2
// and no listening event. Tests: empty, unknown, duplicate, and uppercase
// method names (case-sensitive).
func TestRun_AuthFlagValidation(t *testing.T) {
	cases := []struct {
		name string
		auth string
	}{
		{"empty-string", ""},
		{"unknown-method", "bogus"},
		{"password-plus-unknown", "password,bogus"},
		{"duplicate", "password,password"},
		{"uppercase-rejected", "PASSWORD"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			isolateHome(t)
			args := append([]string{}, defaultGoodArgs()...)
			args = append(args, "--auth", tc.auth)
			_, stderr, rc := runToCompletion(t, args)
			if rc != exitBadConfig {
				t.Fatalf("--auth=%q: rc=%d want %d; stderr=%q", tc.auth, rc, exitBadConfig, stderr)
			}
			// Must not have bound a listener (no listening event).
			if strings.Contains(stderr, " listening ") {
				t.Errorf("--auth=%q: server should not have started; stderr=%q", tc.auth, stderr)
			}
		})
	}
}

// TestRun_AuthPublickeyOnlyNoKeysNoPasswordExitsBadConfig verifies the
// unauthenticable-configuration check: --auth=publickey with no
// authorized-keys file and no password exits 2 with a clear message.
func TestRun_AuthPublickeyOnlyNoKeysNoPasswordExitsBadConfig(t *testing.T) {
	isolateHome(t)
	args := []string{
		"--port", "0",
		"--bind", "127.0.0.1",
		"--user", "testuser",
		"--shell", "/bin/sh",
		"--auth", "publickey",
		// no --authorized-keys → file absent → zero keys
		// no --pass → publickey-only sentinel chosen but still zero keys
	}
	_, stderr, rc := runToCompletion(t, args)
	if rc != exitBadConfig {
		t.Fatalf("rc=%d want %d; stderr=%q", rc, exitBadConfig, stderr)
	}
	if !strings.Contains(stderr, "publickey") {
		t.Errorf("stderr should mention publickey config issue; got %q", stderr)
	}
}

// TestRun_AuthPublickeyMissingKeysFileIsWarning verifies that when --auth
// includes publickey but the authorized-keys file is absent, startup
// proceeds with a WARN log (pubkey-keys-missing). The server must reach
// the listening state since password auth is also available to rescue it.
func TestRun_AuthPublickeyMissingKeysFileIsWarning(t *testing.T) {
	isolateHome(t)
	args := []string{
		"--port", "0",
		"--bind", "127.0.0.1",
		"--pass", "hunter2",
		"--user", "testuser",
		"--shell", "/bin/sh",
		"--auth", "password,publickey",
		"--authorized-keys", "/nonexistent/path/authorized_keys",
	}
	stdout, stderr, rc := runUntilListening(t, args)
	if rc != exitOK {
		t.Fatalf("rc=%d want %d; stderr=%q stdout=%q", rc, exitOK, stderr, stdout)
	}
	// The server must have reached the listening state.
	if !strings.Contains(stdout, " listening ") {
		t.Errorf("expected listening event; stdout=%q", stdout)
	}
	// The server must have emitted a pubkey-keys-missing WARN (logfmt).
	if !strings.Contains(stdout, "pubkey-keys-missing") {
		t.Errorf("expected pubkey-keys-missing WARN event in log; stdout=%q", stdout)
	}
}

// TestRun_DefaultBehaviorMatchesBaseline asserts that running with no new
// pubkey flags produces an identical observable baseline: the listening
// event includes auth_methods=password and pubkey_count=0, no pubkey-*
// events appear, and the exit code is 0 — exactly matching pre-pubkey
// behavior.
func TestRun_DefaultBehaviorMatchesBaseline(t *testing.T) {
	isolateHome(t)
	stdout, stderr, rc := runUntilListening(t, defaultGoodArgs())
	if rc != exitOK {
		t.Fatalf("rc=%d want %d; stderr=%q", rc, exitOK, stderr)
	}
	// auth_methods must default to password.
	if !strings.Contains(stdout, "auth_methods=password") {
		t.Errorf("expected auth_methods=password in listening event; stdout=%q", stdout)
	}
	// pubkey_count must be 0.
	if !strings.Contains(stdout, "pubkey_count=0") {
		t.Errorf("expected pubkey_count=0 in listening event; stdout=%q", stdout)
	}
	// No pubkey-* events must appear.
	for _, unexpected := range []string{"pubkey-keys-missing", "pubkey-parse-error", "pubkey-reload"} {
		if strings.Contains(stdout, unexpected) {
			t.Errorf("unexpected pubkey event %q in default mode; stdout=%q", unexpected, stdout)
		}
	}
	// No Password: banner must appear (--pass was supplied via defaultGoodArgs).
	if strings.Contains(stdout, "Password:") {
		t.Errorf("unexpected Password: banner when --pass is supplied; stdout=%q", stdout)
	}
}

// TestRun_ForwardMaxNegativeExits2 asserts that --forward-max with a negative
// value causes the process to exit with exitBadConfig and a descriptive message.
func TestRun_ForwardMaxNegativeExits2(t *testing.T) {
	isolateHome(t)
	args := append([]string{}, defaultGoodArgs()...)
	args = append(args, "--forward-max", "-1")
	_, stderr, rc := runToCompletion(t, args)
	if rc != exitBadConfig {
		t.Fatalf("rc=%d want %d; stderr=%q", rc, exitBadConfig, stderr)
	}
	if !strings.Contains(stderr, "forward-max") && !strings.Contains(stderr, "forward_max") {
		t.Errorf("stderr should mention forward-max; got %q", stderr)
	}
}

// TestRun_ForwardMaxNonInteger_Env asserts that a non-integer MINISSHD_FORWARD_MAX
// causes the process to exit with exitBadConfig.
func TestRun_ForwardMaxNonInteger_Env(t *testing.T) {
	isolateHome(t)
	unsetenv(t, "MINISSHD_FORWARD_MAX")
	t.Setenv("MINISSHD_FORWARD_MAX", "abc")
	_, stderr, rc := runToCompletion(t, defaultGoodArgs())
	if rc != exitBadConfig {
		t.Fatalf("rc=%d want %d; stderr=%q", rc, exitBadConfig, stderr)
	}
	if !strings.Contains(stderr, "MINISSHD_FORWARD_MAX") {
		t.Errorf("stderr should mention MINISSHD_FORWARD_MAX; got %q", stderr)
	}
}

// TestRun_ForwardMaxDefault32 asserts that when neither --forward-max nor
// MINISSHD_FORWARD_MAX is set, the server starts successfully (default = 32).
func TestRun_ForwardMaxDefault32(t *testing.T) {
	isolateHome(t)
	unsetenv(t, "MINISSHD_FORWARD_MAX")
	_, stderr, rc := runUntilListening(t, defaultGoodArgs())
	if rc != exitOK {
		t.Fatalf("rc=%d want %d; stderr=%q", rc, exitOK, stderr)
	}
}

// TestRun_ForwardMaxFlagBeatsEnv asserts that --forward-max overrides
// MINISSHD_FORWARD_MAX: even with an invalid env value, the flag wins.
func TestRun_ForwardMaxFlagBeatsEnv(t *testing.T) {
	isolateHome(t)
	unsetenv(t, "MINISSHD_FORWARD_MAX")
	t.Setenv("MINISSHD_FORWARD_MAX", "not-a-number")
	args := append([]string{}, defaultGoodArgs()...)
	args = append(args, "--forward-max", "10")
	_, stderr, rc := runUntilListening(t, args)
	if rc != exitOK {
		t.Fatalf("rc=%d want %d (flag should beat env); stderr=%q", rc, exitOK, stderr)
	}
}

// TestRun_ForwardMaxZeroAllowed asserts that --forward-max 0 (forwarding
// disabled) is accepted and the server starts normally.
func TestRun_ForwardMaxZeroAllowed(t *testing.T) {
	isolateHome(t)
	unsetenv(t, "MINISSHD_FORWARD_MAX")
	args := append([]string{}, defaultGoodArgs()...)
	args = append(args, "--forward-max", "0")
	_, stderr, rc := runUntilListening(t, args)
	if rc != exitOK {
		t.Fatalf("rc=%d want %d; stderr=%q", rc, exitOK, stderr)
	}
}

// guard against accidental package init
var _ = errors.Is
