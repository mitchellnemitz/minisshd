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
// The server allows up to 6 combined auth failures per connection before
// disconnecting. A "failure" is any auth attempt the server rejects —
// either a password attempt, a publickey signature failure, or a
// rejected-key pubkey query (the probe where the client asks "would you
// accept this key?" against an unknown key). Password failures, publickey
// signature failures, and rejected-key queries all share a single combined
// authFailures counter in golang.org/x/crypto/ssh. The current library
// (v0.51.0, ssh/server.go lines 843–845) exempts only the mandatory initial
// `none` probe from this counter; every other failure — including
// rejected-key queries — increments authFailures.
//
// Why 6: A typical SSH client (OpenSSH, PuTTY) probes each key in its
// agent with a query before presenting a signature. If the client holds 3
// keys of which 2 are not in the authorized-keys file, the client generates
// 2 rejected-key queries (+2) before signing with the accepted key. With
// MaxAuthTries = 3, those probes consume two of the three slots. Setting
// MaxAuthTries = 6 accommodates up to 3 rejected-key probes plus 3 real
// credential attempts — the rate-limiter's per-IP backoff is the primary
// brute-force defense.
const MaxAuthTries = 6

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
	// Methods is the list of SSH auth methods to advertise. Nil or empty
	// defaults to ["password"] in newServerConfig.
	Methods auth.Methods
	// KeysetSource holds the atomic accepted-public-keys source. Nil when
	// publickey auth is not configured.
	KeysetSource *auth.KeysetSource
}
