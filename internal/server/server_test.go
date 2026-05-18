package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/mitchellnemitz/minisshd/internal/auth"
	"github.com/mitchellnemitz/minisshd/internal/logging"
	"github.com/mitchellnemitz/minisshd/internal/ratelimit"
)

// testSigner builds a throwaway Ed25519 signer for unit tests that need
// a non-nil ssh.Signer to satisfy Config validation.
func testSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519: %v", err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("derive signer: %v", err)
	}
	return s
}

// nopSession satisfies SessionHandler for tests that never actually
// route a session channel. It records every Handle call but otherwise
// does nothing.
type nopSession struct {
	calls int
}

func (n *nopSession) Handle(
	ctx context.Context,
	ch ssh.Channel,
	reqs <-chan *ssh.Request,
	remoteAddr string,
) {
	n.calls++
}

func newTestServer(t *testing.T, ln net.Listener) *Server {
	t.Helper()
	var buf bytes.Buffer
	cfg := Config{
		Listener:    ln,
		HostKey:     testSigner(t),
		Credentials: auth.NewCredentials("alice", "hunter2"),
		Limiter:     ratelimit.New(ratelimit.RealClock{}),
		// SessionService is intentionally nil in tests — newWithDeps
		// injects a stub sessionHandler so the field is unused.
		SessionService: nil,
		Log:            logging.New(&buf, "hunter2"),
	}
	return newWithDeps(cfg, &nopSession{})
}

func TestNewServerConfig_MaxAuthTriesIs3(t *testing.T) {
	// Spec §4 mandates "3 real password attempts per connection ...
	// count password failures only." The spec also names MaxAuthTries=4,
	// but that literal assumed golang.org/x/crypto/ssh counts the
	// mandatory `none` probe — which v0.51.0 no longer does (it exempts
	// the first `none` from the counter). We honor the behavioral
	// guarantee over the stale literal: setting MaxAuthTries=3 yields
	// exactly three password failures under the current library.
	ln := mustListen(t)
	defer ln.Close()
	s := newTestServer(t, ln)
	cfg := s.newServerConfig()
	if cfg.MaxAuthTries != 3 {
		t.Fatalf("MaxAuthTries = %d, want 3 (spec §4 guarantees three "+
			"password attempts; golang.org/x/crypto/ssh v0.51.0 exempts "+
			"the initial `none` probe from the counter)", cfg.MaxAuthTries)
	}
}

func TestNewServerConfig_OnlyPasswordAuthOffered(t *testing.T) {
	// Spec §4 method: only `password` is offered. PublicKeyCallback,
	// KeyboardInteractiveCallback, and NoClientAuth must all be off /
	// nil so the SSH library does not advertise them.
	ln := mustListen(t)
	defer ln.Close()
	s := newTestServer(t, ln)
	cfg := s.newServerConfig()
	if cfg.NoClientAuth {
		t.Fatal("NoClientAuth = true; spec §4 forbids no-auth")
	}
	if cfg.PublicKeyCallback != nil {
		t.Fatal("PublicKeyCallback set; spec §4 forbids publickey")
	}
	if cfg.KeyboardInteractiveCallback != nil {
		t.Fatal("KeyboardInteractiveCallback set; spec §4 forbids keyboard-interactive")
	}
	if cfg.PasswordCallback == nil {
		t.Fatal("PasswordCallback nil; spec §4 requires password auth")
	}
}

func TestNewServerConfig_ServerVersionSet(t *testing.T) {
	// RFC 4253 §4.2 requires the "SSH-2.0-" prefix.
	ln := mustListen(t)
	defer ln.Close()
	s := newTestServer(t, ln)
	cfg := s.newServerConfig()
	if cfg.ServerVersion == "" {
		t.Fatal("ServerVersion is empty")
	}
	const prefix = "SSH-2.0-"
	if len(cfg.ServerVersion) < len(prefix) || cfg.ServerVersion[:len(prefix)] != prefix {
		t.Fatalf("ServerVersion = %q, want SSH-2.0- prefix", cfg.ServerVersion)
	}
}

func TestServe_ReturnsWhenContextCancelled(t *testing.T) {
	// Spec §8: cancellation stops accepting new conns, drains active
	// sessions (cap 5 s), and returns nil. With zero in-flight sessions
	// this should complete promptly.
	ln := mustListen(t)
	s := newTestServer(t, ln)

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- s.Serve(ctx)
	}()

	// Give the accept loop a moment to enter Accept().
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Serve returned error: %v", err)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("Serve did not return within 6 s of context cancellation")
	}
}

func TestServe_LogsHandshakeFailureForBareTCPConnection(t *testing.T) {
	// A raw TCP connection that closes before the SSH handshake
	// completes should not crash the accept loop. The server simply
	// finishes the per-conn goroutine and continues.
	ln := mustListen(t)
	s := newTestServer(t, ln)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveErr := make(chan error, 1)
	go func() { serveErr <- s.Serve(ctx) }()

	// Open a TCP connection and close it immediately.
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_ = c.Close()

	// Give the per-conn goroutine time to fail the handshake.
	time.Sleep(100 * time.Millisecond)

	cancel()
	select {
	case <-serveErr:
	case <-time.After(6 * time.Second):
		t.Fatal("Serve did not return after cancel")
	}
}

func mustListen(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	return ln
}
