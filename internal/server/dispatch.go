package server

import "golang.org/x/crypto/ssh"

// Channel-type constants from RFC 4254 + OpenSSH extensions. Spec §7
// lists the channel-open types that must be explicitly rejected or forwarded.
const (
	channelTypeSession            = "session"
	channelTypeDirectTCPIP        = "direct-tcpip"
	channelTypeForwardedTCPIP     = "forwarded-tcpip"
	channelTypeDirectStreamlocal  = "direct-streamlocal@openssh.com"
	channelTypeStreamlocalForward = "streamlocal-forward@openssh.com"
)

// channelAction is the tri-state result of classifyChannel.
type channelAction int

const (
	actionRejected channelAction = iota
	actionSession
	actionForward
)

// Global request types from RFC 4254 §7.1 that must be rejected: remote
// port forwarding setup and teardown.
const (
	globalRequestTCPIPForward       = "tcpip-forward"
	globalRequestCancelTCPIPForward = "cancel-tcpip-forward"
)

// rejectLogger captures the single logging method the dispatcher needs.
// Mirrors authLogger's testability pattern.
type rejectLogger interface {
	Reject(remote, what string)
}

// newChannel is the package-private interface that lets unit tests
// substitute a stub for ssh.NewChannel without constructing real wire
// messages. The concrete *ssh.NewChannel satisfies this trivially.
type newChannel interface {
	ChannelType() string
	Reject(reason ssh.RejectionReason, message string) error
}

// newChannelExt is the subset of ssh.NewChannel that the forward handler
// needs: ChannelType and Reject (from newChannel), plus ExtraData and
// Accept. Tests substitute a fake.
type newChannelExt interface {
	newChannel
	ExtraData() []byte
	Accept() (ssh.Channel, <-chan *ssh.Request, error)
}

// Compile-time assertion: the real ssh.NewChannel satisfies the extended
// surface.
var _ newChannelExt = (ssh.NewChannel)(nil)

// rejectableRequest is the subset of *ssh.Request the dispatcher uses
// when handling global requests. Spec §7 only requires reply(false);
// constructing a real *ssh.Request in tests is awkward because the
// internal `mux` pointer is unexported, so we work through an interface.
type rejectableRequest interface {
	Reqtype() string
	WantsReply() bool
	Deny() error
}

// globalRequest is the dispatcher-visible facade over *ssh.Request used
// by handleGlobalRequest. The concrete sshRequestAdapter wraps a real
// request for the production path; tests use their own fake.
type globalRequest = rejectableRequest

// sshRequestAdapter adapts a *ssh.Request to the rejectableRequest
// interface. Reply(false, nil) is a no-op when WantReply is false, per
// the x/crypto/ssh contract — same as for channel requests.
type sshRequestAdapter struct{ r *ssh.Request }

func (a sshRequestAdapter) Reqtype() string  { return a.r.Type }
func (a sshRequestAdapter) WantsReply() bool { return a.r.WantReply }
func (a sshRequestAdapter) Deny() error      { return a.r.Reply(false, nil) }

// classifyChannel performs the §7 routing: session → actionSession,
// direct-tcpip → actionForward, everything else → actionRejected (and
// rejected here with the appropriate log event). The direct-tcpip arm
// does NOT call log.Reject — forward open/reject events are owned by
// forward.go.
func classifyChannel(ch newChannel, remote string, log rejectLogger) channelAction {
	switch ch.ChannelType() {
	case channelTypeSession:
		return actionSession
	case channelTypeDirectTCPIP:
		return actionForward
	case channelTypeForwardedTCPIP:
		log.Reject(remote, "tcpip")
		_ = ch.Reject(ssh.Prohibited, "port forwarding not supported")
		return actionRejected
	case channelTypeDirectStreamlocal, channelTypeStreamlocalForward:
		log.Reject(remote, "streamlocal")
		_ = ch.Reject(ssh.Prohibited, "unix-socket forwarding not supported")
		return actionRejected
	default:
		log.Reject(remote, ch.ChannelType())
		_ = ch.Reject(ssh.UnknownChannelType, "unknown channel type")
		return actionRejected
	}
}

// routeChannel is a thin wrapper around classifyChannel that returns true
// iff the action is actionSession. This preserves the existing test surface
// (TestRouteChannel_*) without modification.
func routeChannel(ch newChannel, remote string, log rejectLogger) (accepted bool) {
	return classifyChannel(ch, remote, log) == actionSession
}

// handleGlobalRequest replies false to every inbound global request and
// emits a `reject what=tcpip` event for the two RFC 4254 port-forwarding
// requests. Other global request types are silently denied — spec §9
// does not require a log entry for an arbitrary unknown global request
// (most clients send keepalive `keepalive@openssh.com` on the global
// channel, which is noise rather than something to flag).
func handleGlobalRequest(req rejectableRequest, remote string, log rejectLogger) {
	switch req.Reqtype() {
	case globalRequestTCPIPForward, globalRequestCancelTCPIPForward:
		log.Reject(remote, "tcpip")
	}
	_ = req.Deny()
}

// Static type checks for the adapters.
var _ rejectLogger = (rejectLoggerFunc)(nil)

// rejectLoggerFunc lets tests build a rejectLogger from a closure without
// declaring a struct.
type rejectLoggerFunc func(remote, what string)

func (f rejectLoggerFunc) Reject(remote, what string) { f(remote, what) }
