package logging_test

// Mirror of the §13.3 in-process test harness; same shape as the helper
// in internal/server/testhelpers_integration_test.go.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
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
	user     string
	password string
	shell    string
	bind     string
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
	for _, p := range []string{"/bin/zsh", "/bin/bash", "/bin/sh"} {
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

func countLogOccurrences(logBuf *syncBuffer, substr string) int {
	return strings.Count(logBuf.String(), substr)
}
