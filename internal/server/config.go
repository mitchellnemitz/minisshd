package server

import (
	"context"
	"net"

	"golang.org/x/crypto/ssh"

	"github.com/mitchellnemitz/minisshd/internal/auth"
	"github.com/mitchellnemitz/minisshd/internal/logging"
	"github.com/mitchellnemitz/minisshd/internal/ratelimit"
	"github.com/mitchellnemitz/minisshd/internal/session"
)

// sessionHandler is the boundary between the server (this package,
// owner of the connection-level lifecycle) and the session package
// (owner of the §8 PTY/exec/SFTP machinery). The concrete
// *session.Service satisfies this interface, but defining it locally
// gives unit tests a seam for substituting a recording stub without
// spinning up the real PTY/SFTP machinery.
//
// The contract is identical to session.Service.Handle: take ownership
// of an accepted "session" channel, route pty-req/env/shell/exec/
// subsystem per §8, manage the child lifecycle (drain caps, SIGHUP on
// shutdown, exit-status delivery), and return when both the channel
// and child have settled. ctx cancellation is the server-shutdown
// signal — the session forwards SIGHUP to its child and gives it up to
// 5 s before SIGKILL.
type sessionHandler interface {
	Handle(
		ctx context.Context,
		ch ssh.Channel,
		reqs <-chan *ssh.Request,
		remoteAddr string,
	)
}

// Compile-time assertion that the concrete session.Service satisfies
// the local sessionHandler seam. If the signature ever changes, this
// fails to build here rather than at the call site.
var _ sessionHandler = (*session.Service)(nil)

// ServerVersion is the SSH identification string we announce in the
// public handshake. RFC 4253 §4.2 requires the "SSH-2.0-" prefix.
const ServerVersion = "SSH-2.0-minisshd"

// MaxAuthTries is the value set on ssh.ServerConfig.MaxAuthTries.
//
// Spec §4 mandates the behavioral guarantee: "3 real password attempts
// per connection ... count password failures only." The spec also names
// MaxAuthTries = 4 as the value to use, justified by the claim that
// golang.org/x/crypto/ssh increments the counter on the mandatory `none`
// probe. That claim is stale: the current library (v0.51.0) exempts the
// first `none` from the counter (server.go: "Allow initial attempt of
// 'none' without penalty."). With MaxAuthTries = 4 the server would
// deliver four password failures, violating the behavioral guarantee.
//
// We therefore set MaxAuthTries = 3, which produces exactly three
// password attempts under v0.51.0 — honoring the spec's load-bearing
// rule ("count password failures only") over its now-stale literal
// value. The §13.3 integration test asserts the count is exactly 3.
const MaxAuthTries = 3

// Config bundles the wiring inputs the server needs. cmd/minisshd
// constructs this with a bound listener, a loaded host key, the auth
// credentials, the per-IP rate limiter, the session service, and a
// shared logger. None of the fields may be nil — the constructor relies
// on every dependency being present.
type Config struct {
	// Listener is the already-bound listening socket. cmd/minisshd owns
	// listener creation (binding, IPV6_V6ONLY=0, etc.); the server only
	// runs the accept loop on it and closes it during shutdown.
	Listener net.Listener
	// HostKey is the Ed25519 host signer from internal/hostkey.
	HostKey ssh.Signer
	// Credentials holds the cached SHA-256 digests for password/user
	// comparison.
	Credentials *auth.Credentials
	// Limiter is the per-IP exponential-backoff state machine.
	Limiter *ratelimit.Limiter
	// SessionService routes accepted "session" channels to the §8
	// PTY/exec/SFTP machinery. cmd/minisshd passes the concrete
	// *session.Service here.
	SessionService *session.Service
	// Log is the structured logger.
	Log *logging.Logger
}
