package session_test

// Shared §13.3 integration-test harness for the session package. The
// shape mirrors internal/server/testhelpers_integration_test.go and
// internal/auth/testhelpers_integration_test.go so each package's
// integration suite can stand on its own.

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

type testServerOptions struct {
	user      string
	password  string
	shell     string
	logFormat logging.Format
}

type testServer struct {
	addr     string
	user     string
	password string
	logBuf   *syncBuffer
	cleanup  func()
}

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

	logBuf := &syncBuffer{}
	logger := logging.New(logBuf, opts.password, opts.logFormat)
	creds := auth.NewCredentials(opts.user, opts.password)
	limiter := ratelimit.New(ratelimit.RealClock{})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}

	srv := server.New(server.Config{
		Listener:       listener,
		HostKey:        signer,
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
		cleanup:  cleanup,
	}
}

func discoverShell(t *testing.T) string {
	t.Helper()
	for _, p := range []string{"/bin/bash", "/bin/sh", "/bin/zsh"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	t.Skip("no usable shell found")
	return ""
}

func clientConfig(user, password string) *ssh.ClientConfig {
	return &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         15 * time.Second,
	}
}

func dialSSH(t *testing.T, addr string, cfg *ssh.ClientConfig) *ssh.Client {
	t.Helper()
	cli, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		t.Fatalf("ssh.Dial(%s): %v", addr, err)
	}
	return cli
}

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

// isExitErr returns the *ssh.ExitError if err wraps one, else (nil, false).
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

// runOnSession mirrors the server-package helper: Start, read stdout/
// stderr to EOF, then Wait. With commit 3aef20b the server closes the
// channel after exit-status so EOF arrives naturally.
func runOnSession(t *testing.T, sess *ssh.Session, cmd string) (string, string, error) {
	t.Helper()
	stdout, err := sess.StdoutPipe()
	if err != nil {
		return "", "", err
	}
	stderr, err := sess.StderrPipe()
	if err != nil {
		return "", "", err
	}
	if err := sess.Start(cmd); err != nil {
		return "", "", err
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
		t.Fatalf("runOnSession: timed out waiting for stdout on %q", cmd)
	}
	select {
	case r := <-errCh:
		errBytes = r.data
	case <-time.After(15 * time.Second):
		t.Fatalf("runOnSession: timed out waiting for stderr on %q", cmd)
	}
	waitDone := make(chan error, 1)
	go func() { waitDone <- sess.Wait() }()
	var waitErr error
	select {
	case waitErr = <-waitDone:
	case <-time.After(10 * time.Second):
		_ = sess.Close()
	}
	return string(outBytes), string(errBytes), waitErr
}
