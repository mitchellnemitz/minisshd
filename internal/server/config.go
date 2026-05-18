package server

import (
	"context"
	"net"

	"golang.org/x/crypto/ssh"

	"github.com/mitchellnemitz/minissh/internal/auth"
	"github.com/mitchellnemitz/minissh/internal/logging"
	"github.com/mitchellnemitz/minissh/internal/ratelimit"
	"github.com/mitchellnemitz/minissh/internal/session"
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
// the local sessionHandler seam. If session-impl ever changes the
// signature this fails to build here rather than at the call site.
var _ sessionHandler = (*session.Service)(nil)

// ServerVersion is the SSH identification string we announce in the
// public handshake. RFC 4253 §4.2 requires the "SSH-2.0-" prefix.
const ServerVersion = "SSH-2.0-minissh"

// MaxAuthTries is the value set on ssh.ServerConfig.MaxAuthTries. Spec §4
// requires 4 (one mandatory `none` probe + three real password attempts):
// setting 3 would deliver only two password attempts because
// golang.org/x/crypto/ssh increments the counter on the `none` probe too.
const MaxAuthTries = 4

// Config bundles the wiring inputs the server needs. cmd/minissh
// constructs this with a bound listener, a loaded host key, the auth
// credentials, the per-IP rate limiter, the session service, and a
// shared logger. None of the fields may be nil — the constructor relies
// on every dependency being present.
type Config struct {
	// Listener is the already-bound listening socket. cmd/minissh owns
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
	// PTY/exec/SFTP machinery. cmd/minissh passes the concrete
	// *session.Service here.
	SessionService *session.Service
	// Log is the structured logger.
	Log *logging.Logger
}
