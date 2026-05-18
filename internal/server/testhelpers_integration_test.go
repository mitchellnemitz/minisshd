package server_test

// Shared §13.3 integration-test harness. The helpers here spin up the
// in-process server on 127.0.0.1:0 (or a caller-supplied bind), wire a
// real *ratelimit.Limiter / *auth.Credentials / *logging.Logger, generate
// a one-off Ed25519 host key, and run server.Serve in a goroutine.
//
// The same shape is duplicated (intentionally, to keep test ownership
// strict) in internal/auth, internal/ratelimit, and internal/logging.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/mitchellnemitz/minisshd/internal/auth"
	"github.com/mitchellnemitz/minisshd/internal/logging"
	"github.com/mitchellnemitz/minisshd/internal/ratelimit"
	"github.com/mitchellnemitz/minisshd/internal/server"
	"github.com/mitchellnemitz/minisshd/internal/session"
)

// testServerOptions parameterizes startTestServer for the scenarios that
// need to customize user/password/shell/bind. Zero values fall back to
// sensible defaults so most call sites can `startTestServer(t)`.
type testServerOptions struct {
	user     string
	password string
	shell    string
	bind     string // empty -> 127.0.0.1
}

// testServer is everything a §13.3 test needs to drive the in-process
// server: the bound address, a buffer with all the logger's output, the
// shared limiter (so the IPv4-mapped IPv6 test can inspect its
// Snapshot()), and a cleanup func to stop the server.
type testServer struct {
	addr     string
	user     string
	password string
	logBuf   *syncBuffer
	limiter  *ratelimit.Limiter
	cleanup  func()
}

// syncBuffer is a goroutine-safe *bytes.Buffer wrapper. The logger writes
// from server goroutines while tests read concurrently; without a lock
// the race detector flags it.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// startTestServer launches an in-process server. It blocks until the
// listener is bound and the accept loop is running, so the returned addr
// is immediately dialable.
func startTestServer(t *testing.T, opts testServerOptions) *testServer {
	t.Helper()

	if opts.user == "" {
		opts.user = "testuser"
	}
	if opts.password == "" {
		opts.password = "testpass"
	}
	if opts.shell == "" {
		opts.shell = discoverShell(t)
	}
	if opts.bind == "" {
		opts.bind = "127.0.0.1"
	}

	logBuf := &syncBuffer{}
	logger := logging.New(logBuf, opts.password)
	creds := auth.NewCredentials(opts.user, opts.password)
	limiter := ratelimit.New(ratelimit.RealClock{})

	listener, err := net.Listen("tcp", net.JoinHostPort(opts.bind, "0"))
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	hostSigner := generateTestHostKey(t)

	srv := server.New(server.Config{
		Listener:       listener,
		HostKey:        hostSigner,
		Credentials:    creds,
		Limiter:        limiter,
		SessionService: &session.Service{Shell: opts.shell, Log: logger},
		Log:            logger,
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = srv.Serve(ctx)
	}()

	cleanup := func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Errorf("server did not shut down within 10s")
		}
		_ = listener.Close()
	}

	return &testServer{
		addr:     listener.Addr().String(),
		user:     opts.user,
		password: opts.password,
		logBuf:   logBuf,
		limiter:  limiter,
		cleanup:  cleanup,
	}
}

// generateTestHostKey returns an Ed25519 ssh.Signer backed by a fresh in-
// memory keypair. Nothing touches disk.
func generateTestHostKey(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	return signer
}

// discoverShell picks /bin/zsh if present, else /bin/bash, else /bin/sh.
// Tests that explicitly need zsh check shellIsZsh and skip otherwise.
func discoverShell(t *testing.T) string {
	t.Helper()
	for _, p := range []string{"/bin/zsh", "/bin/bash", "/bin/sh"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	t.Skip("no usable shell (/bin/zsh, /bin/bash, /bin/sh) found")
	return ""
}

// clientConfig builds an ssh.ClientConfig wired with a single password
// attempt. Tests that need multi-attempt or wrong-credential clients
// build their own config.
func clientConfig(user, password string) *ssh.ClientConfig {
	return &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         15 * time.Second,
	}
}

// dialSSH wraps ssh.Dial with a clean error message; many tests use it
// as the entry point.
func dialSSH(t *testing.T, addr string, cfg *ssh.ClientConfig) *ssh.Client {
	t.Helper()
	cli, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		t.Fatalf("ssh.Dial(%s): %v", addr, err)
	}
	return cli
}

// waitForLog spins reading logBuf.String() until substr appears or the
// timeout elapses. Returns the matched offset (>=0) on success, -1 on
// timeout. Many §13.3 cases need this rather than a single read because
// the logger emits from a different goroutine.
func waitForLog(t *testing.T, logBuf *syncBuffer, substr string, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if strings.Contains(logBuf.String(), substr) {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

// countLogOccurrences counts the number of times substr appears in the
// captured log buffer.
func countLogOccurrences(logBuf *syncBuffer, substr string) int {
	return strings.Count(logBuf.String(), substr)
}

// isExitErr returns true if err is an *ssh.ExitError or an *ssh.ExitMissingError.
func isExitErr(err error) (*ssh.ExitError, bool) {
	if err == nil {
		return nil, false
	}
	var ee *ssh.ExitError
	if errors.As(err, &ee) {
		return ee, true
	}
	return nil, false
}

// waitSession bounds sess.Wait() with a hard timeout. Commit 3aef20b
// fixed the prior deadlock by having the server close the channel after
// sending exit-status, so Wait now returns naturally for both x/crypto
// and OpenSSH clients. The timeout remains as a defensive guard against
// regressions; the returned bool reports whether the timeout fired.
func waitSession(t *testing.T, sess *ssh.Session, timeout time.Duration) (err error, timedOut bool) {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		done <- sess.Wait()
	}()
	select {
	case err = <-done:
		return err, false
	case <-time.After(timeout):
		_ = sess.Close()
		select {
		case err = <-done:
		case <-time.After(2 * time.Second):
		}
		return err, true
	}
}

// runOnSession runs cmd via exec and returns (stdout+stderr, exit-error).
//
// With the session-close-after-exit-status fix in 3aef20b the natural
// flow works: the client reads stdout/stderr to EOF (which the server
// triggers by closing the channel after sendExit), then Wait() returns
// the *ssh.ExitError carrying the exit-status. No force-close needed.
func runOnSession(t *testing.T, sess *ssh.Session, cmd string) (string, error) {
	t.Helper()
	stdout, err := sess.StdoutPipe()
	if err != nil {
		return "", err
	}
	stderr, err := sess.StderrPipe()
	if err != nil {
		return "", err
	}
	if err := sess.Start(cmd); err != nil {
		return "", err
	}

	type res struct{ data []byte }
	outCh := make(chan res, 1)
	errCh := make(chan res, 1)
	go func() { b, _ := io.ReadAll(stdout); outCh <- res{b} }()
	go func() { b, _ := io.ReadAll(stderr); errCh <- res{b} }()

	var outBytes, errBytes []byte
	select {
	case r := <-outCh:
		outBytes = r.data
	case <-time.After(15 * time.Second):
		t.Fatalf("runOnSession: timed out waiting for stdout EOF on cmd %q", cmd)
	}
	select {
	case r := <-errCh:
		errBytes = r.data
	case <-time.After(15 * time.Second):
		t.Fatalf("runOnSession: timed out waiting for stderr EOF on cmd %q", cmd)
	}

	waitErr, _ := waitSession(t, sess, 10*time.Second)
	return string(outBytes) + string(errBytes), waitErr
}
