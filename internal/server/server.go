package server

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/mitchellnemitz/minisshd/internal/auth"
)

// drainTimeout is the cap §8 allots for sessions to finish after the
// server context cancels. The session goroutines own their own SIGHUP →
// 5 s → SIGKILL flow; this is the outer waiter.
const drainTimeout = 5 * time.Second

// Server runs the §3 listening socket and the §7 channel/request
// dispatch. It is constructed via New and started via Serve.
//
// Lifecycle (per spec §8 Signal handling, server side):
//
//  1. Serve enters the accept loop.
//  2. When the caller's ctx cancels, Serve closes the listener (which
//     unblocks Accept with a net.ErrClosed) and cancels the inner
//     connections context.
//  3. Inner per-session contexts derive from that inner connections
//     context, so cancellation propagates into each running session
//     where the session implementation performs its own drain.
//  4. Serve waits up to drainTimeout for in-flight sessions to settle,
//     then returns nil regardless.
type Server struct {
	cfg Config

	// Production hooks. The constructor wires real implementations; tests
	// override the seams via newWithDeps.
	limiter rateLimiter
	creds   credentialChecker
	session sessionHandler
	sleep   sleeper
}

// New constructs a Server from cfg. The caller is responsible for the
// validity of every Config field. The returned Server is inert until
// Serve is invoked.
func New(cfg Config) *Server {
	sleep := cfg.Sleep
	if sleep == nil {
		sleep = time.Sleep
	}
	return &Server{
		cfg:     cfg,
		limiter: cfg.Limiter,
		creds:   cfg.Credentials,
		session: cfg.SessionService,
		sleep:   sleep,
	}
}

// newWithDeps is the test-only constructor that lets unit tests replace
// the session handler with a recording stub. Production code uses New,
// which wires the concrete *session.Service from Config.
func newWithDeps(cfg Config, session sessionHandler) *Server {
	s := New(cfg)
	s.session = session
	return s
}

// newServerConfig builds the ssh.ServerConfig the accept loop hands to
// ssh.NewServerConn. Separated from New so unit tests can inspect the
// fields without spinning up a listener.
//
// Config.Methods nil/empty defaults to ["password"], preserving pre-pubkey
// behavior. Both PasswordCallback and PublicKeyCallback may be set
// simultaneously; the SSH library advertises all configured methods and
// the client picks any one.
func (s *Server) newServerConfig() *ssh.ServerConfig {
	methods := s.cfg.Methods
	if len(methods) == 0 {
		methods = auth.Methods{auth.MethodPassword}
	}

	cfg := &ssh.ServerConfig{
		NoClientAuth:  false,
		MaxAuthTries:  MaxAuthTries,
		ServerVersion: ServerVersion,
	}
	if methods.Contains(auth.MethodPassword) {
		cfg.PasswordCallback = passwordCallback(s.limiter, s.creds, s.cfg.Log, s.sleep)
	}
	if methods.Contains(auth.MethodPublickey) && s.cfg.KeysetSource != nil {
		cfg.PublicKeyCallback = publickeyCallback(s.limiter, s.creds, s.cfg.KeysetSource, s.cfg.Log, s.sleep)
	}
	cfg.AddHostKey(s.cfg.HostKey)
	return cfg
}

// Serve runs the accept loop until ctx is cancelled. On cancellation it
// closes the listener (interrupting the blocked Accept), cancels every
// per-session context, and waits up to drainTimeout for those sessions
// to finish. The 5 s timeout is not surfaced as an error — per-session
// drain timeouts are logged by the session owner.
func (s *Server) Serve(ctx context.Context) error {
	sshConfig := s.newServerConfig()

	// connsCtx fans out to every per-connection goroutine. We cancel it
	// inside the shutdown path after closing the listener so the
	// connection goroutines can wind down their own session children.
	connsCtx, cancelConns := context.WithCancel(context.Background())
	defer cancelConns()

	// sessionsWG tracks every session goroutine across all connections,
	// so Serve can wait on a single waitgroup at shutdown.
	var sessionsWG sync.WaitGroup

	// Shutdown watcher: when the user's ctx cancels, close the listener
	// and cancel the connections context. Done via a goroutine so the
	// accept loop below stays simple.
	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		<-ctx.Done()
		_ = s.cfg.Listener.Close()
		cancelConns()
	}()

	// Accept loop. Each accepted net.Conn becomes a per-connection
	// goroutine.
	var connsWG sync.WaitGroup
	for {
		nc, err := s.cfg.Listener.Accept()
		if err != nil {
			// net.ErrClosed is the expected shutdown path; anything
			// else is a real I/O error. Either way the accept loop
			// terminates here.
			if !errors.Is(err, net.ErrClosed) {
				s.cfg.Log.Error("accept: "+err.Error(), "")
			}
			break
		}
		connsWG.Add(1)
		go func(c net.Conn) {
			defer connsWG.Done()
			s.handleConn(connsCtx, c, sshConfig, &sessionsWG)
		}(nc)
	}

	// Listener has stopped. Make sure cancelConns has run (it will have
	// been triggered by the watcher; this defer-style call is harmless).
	cancelConns()

	// Wait for connection goroutines to wind down so their session
	// children get a chance to start their own drain. We bound this with
	// drainTimeout — sessions that exceed it record their own
	// drain-timeout event.
	connsDone := make(chan struct{})
	go func() {
		connsWG.Wait()
		sessionsWG.Wait()
		close(connsDone)
	}()
	drain := s.cfg.DrainTimeout
	if drain == 0 {
		drain = drainTimeout
	}
	select {
	case <-connsDone:
	case <-time.After(drain):
	}

	// Wait for the shutdown watcher to exit cleanly. If ctx was never
	// cancelled (e.g. listener error broke the loop), nudge it ourselves
	// so the watcher's select returns.
	select {
	case <-shutdownDone:
	default:
		// ctx is still live; cancelConns above will have run but the
		// watcher waits on ctx.Done. Give it a beat to exit; in
		// practice the parent ctx is always cancelled before Serve
		// returns in production use.
		select {
		case <-shutdownDone:
		case <-time.After(100 * time.Millisecond):
		}
	}

	return nil
}

// handleConn drives one accepted TCP connection through the SSH
// handshake and channel dispatch loop. It returns when both the channel
// loop exits and every session goroutine on the connection has joined,
// matching the spec §9 `conn-close` semantics where duration is the
// time from accept to teardown.
func (s *Server) handleConn(
	ctx context.Context,
	nc net.Conn,
	sshConfig *ssh.ServerConfig,
	sessionsWG *sync.WaitGroup,
) {
	start := time.Now()
	remote := nc.RemoteAddr().String()
	s.cfg.Log.ConnOpen(remote)

	// On any exit path we log conn-close and close the underlying
	// connection. The handshake takes care of closing the conn itself
	// on failure, but a defensive Close is cheap and harmless.
	defer func() {
		_ = nc.Close()
		s.cfg.Log.ConnClose(remote, time.Since(start))
	}()

	serverConn, chans, globalReqs, err := ssh.NewServerConn(nc, sshConfig)
	if err != nil {
		// Auth failures are already logged by the password callback.
		// Anything else (handshake error, transport error) is worth a
		// generic error event so operators see something.
		if !isExpectedHandshakeError(err) {
			s.cfg.Log.Error("handshake: "+err.Error(), remote)
		}
		return
	}
	defer func() { _ = serverConn.Close() }()

	// Discard global requests. tcpip-forward and cancel-tcpip-forward
	// are explicitly rejected per §7 with a `reject what=tcpip` log
	// event; other global requests (keepalives, etc.) are silently
	// denied.
	go func() {
		for req := range globalReqs {
			handleGlobalRequest(sshRequestAdapter{r: req}, remote, s.cfg.Log)
		}
	}()

	// Per-connection sessions context: cancellation cascades from ctx
	// (server shutdown) into every active session on this connection.
	connCtx, cancelConn := context.WithCancel(ctx)
	defer cancelConn()

	// fwdCap tracks concurrent direct-tcpip channels on this connection.
	// Named fwdCap (not forwardCounter) to avoid shadowing the type name.
	fwdCap := &forwardCounter{cap: s.cfg.ForwardMax}

	// Channel accept loop. Classify each inbound NewChannel and dispatch:
	// sessions go to the session service; direct-tcpip channels go to the
	// forward handler; everything else is already rejected inside
	// classifyChannel.
	for newCh := range chans {
		switch classifyChannel(newCh, remote, s.cfg.Log) {
		case actionSession:
			channel, reqs, err := newCh.Accept()
			if err != nil {
				s.cfg.Log.Error("accept channel: "+err.Error(), remote)
				continue
			}
			sessionsWG.Add(1)
			go func() {
				defer sessionsWG.Done()
				s.session.Handle(connCtx, channel, reqs, remote)
			}()
		case actionForward:
			nc := newCh // capture for goroutine
			sessionsWG.Add(1)
			go func(nc ssh.NewChannel) {
				defer sessionsWG.Done()
				handleDirectTCPIP(connCtx, nc, remote, fwdCap, s.cfg.Log)
			}(nc)
		case actionRejected:
			// already handled inside classifyChannel
		}
	}
}

// isExpectedHandshakeError reports whether err is one of the "client
// went away" or "auth exhausted" paths the SSH library returns during
// the handshake. We don't want to spam `error` events for those — they
// are normal traffic.
func isExpectedHandshakeError(err error) bool {
	if err == nil {
		return true
	}
	// MaxAuthTries-exceeded surfaces as *ssh.ServerAuthError. Treat any
	// auth-related error as expected; the password callback has already
	// logged the per-attempt failures.
	var authErr *ssh.ServerAuthError
	if errors.As(err, &authErr) {
		return true
	}
	// io.EOF and io.ErrUnexpectedEOF show up when the client TCP-resets
	// during handshake (port scanners, broken probes). These are not
	// worth logging.
	msg := err.Error()
	switch msg {
	case "EOF", "unexpected EOF":
		return true
	}
	return false
}
