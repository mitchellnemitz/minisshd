package server

import (
	"errors"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
)

// fakeNewChannel is a stub ssh.NewChannel. The real ssh.NewChannel is
// an interface, but its concrete implementation requires a live mux so
// we can't instantiate one. routeChannel takes our package-private
// newChannel interface, which this satisfies.
type fakeNewChannel struct {
	chanType string

	mu         sync.Mutex
	rejected   bool
	reason     ssh.RejectionReason
	rejectMsg  string
	rejectErr  error
	rejectFail bool
}

func (f *fakeNewChannel) ChannelType() string { return f.chanType }

func (f *fakeNewChannel) Reject(reason ssh.RejectionReason, message string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rejected = true
	f.reason = reason
	f.rejectMsg = message
	if f.rejectFail {
		return errors.New("injected")
	}
	return f.rejectErr
}

// fakeRequest implements rejectableRequest for testing
// handleGlobalRequest.
type fakeRequest struct {
	t          string
	wantReply  bool
	deniedOnce bool
}

func (r *fakeRequest) Reqtype() string  { return r.t }
func (r *fakeRequest) WantsReply() bool { return r.wantReply }
func (r *fakeRequest) Deny() error      { r.deniedOnce = true; return nil }

// recordingRejectLogger captures every Reject(remote, what) call.
type recordingRejectLogger struct {
	mu    sync.Mutex
	calls []rejectCall
}

type rejectCall struct{ remote, what string }

func (r *recordingRejectLogger) Reject(remote, what string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, rejectCall{remote, what})
}

func TestRouteChannel_SessionAccepted(t *testing.T) {
	t.Parallel()
	ch := &fakeNewChannel{chanType: "session"}
	log := &recordingRejectLogger{}

	if !routeChannel(ch, "10.0.0.1:22", log) {
		t.Fatal("routeChannel returned false for session; want true")
	}
	if ch.rejected {
		t.Fatal("session channel must not be rejected")
	}
	if len(log.calls) != 0 {
		t.Fatalf("session must not be logged as reject; got %+v", log.calls)
	}
}

// TestRouteChannel_RejectsForwardedTCPIP asserts that forwarded-tcpip is
// rejected. direct-tcpip is no longer rejected (it routes to actionForward).
func TestRouteChannel_RejectsForwardedTCPIP(t *testing.T) {
	t.Parallel()
	for _, ct := range []string{"forwarded-tcpip"} {
		t.Run(ct, func(t *testing.T) {
			ch := &fakeNewChannel{chanType: ct}
			log := &recordingRejectLogger{}
			if routeChannel(ch, "1.2.3.4:5", log) {
				t.Fatal("expected routeChannel to return false")
			}
			if !ch.rejected {
				t.Fatal("expected Reject to be called")
			}
			if ch.reason != ssh.Prohibited {
				t.Fatalf("reject reason = %v, want Prohibited", ch.reason)
			}
			if len(log.calls) != 1 || log.calls[0].what != "tcpip" {
				t.Fatalf("reject log = %+v, want one tcpip entry", log.calls)
			}
		})
	}
}

// TestClassifyChannel_DirectTCPIPRoutedToForward asserts that classifyChannel
// returns actionForward for direct-tcpip and does NOT call Reject or log.Reject.
func TestClassifyChannel_DirectTCPIPRoutedToForward(t *testing.T) {
	t.Parallel()
	ch := &fakeNewChannel{chanType: "direct-tcpip"}
	log := &recordingRejectLogger{}
	action := classifyChannel(ch, "1.2.3.4:5", log)
	if action != actionForward {
		t.Fatalf("classifyChannel returned %v, want actionForward", action)
	}
	if ch.rejected {
		t.Fatal("direct-tcpip channel must not be rejected by classifyChannel")
	}
	if len(log.calls) != 0 {
		t.Fatalf("direct-tcpip must not emit a reject log; got %+v", log.calls)
	}
}

// TestClassifyChannel_SessionRoutedToSession asserts that classifyChannel
// returns actionSession for "session" and does not reject the channel.
func TestClassifyChannel_SessionRoutedToSession(t *testing.T) {
	t.Parallel()
	ch := &fakeNewChannel{chanType: "session"}
	log := &recordingRejectLogger{}
	action := classifyChannel(ch, "1.2.3.4:5", log)
	if action != actionSession {
		t.Fatalf("classifyChannel returned %v, want actionSession", action)
	}
	if ch.rejected {
		t.Fatal("session channel must not be rejected")
	}
	if len(log.calls) != 0 {
		t.Fatalf("session must not log reject; got %+v", log.calls)
	}
}

func TestRouteChannel_RejectsStreamlocal(t *testing.T) {
	t.Parallel()
	for _, ct := range []string{
		"direct-streamlocal@openssh.com",
		"streamlocal-forward@openssh.com",
	} {
		t.Run(ct, func(t *testing.T) {
			ch := &fakeNewChannel{chanType: ct}
			log := &recordingRejectLogger{}
			if routeChannel(ch, "1.2.3.4:5", log) {
				t.Fatal("expected routeChannel to return false")
			}
			if !ch.rejected {
				t.Fatal("expected Reject to be called")
			}
			if len(log.calls) != 1 || log.calls[0].what != "streamlocal" {
				t.Fatalf("reject log = %+v, want one streamlocal entry", log.calls)
			}
		})
	}
}

func TestRouteChannel_RejectsUnknownType(t *testing.T) {
	t.Parallel()
	ch := &fakeNewChannel{chanType: "random-thing"}
	log := &recordingRejectLogger{}
	if routeChannel(ch, "remote", log) {
		t.Fatal("expected routeChannel to return false")
	}
	if !ch.rejected {
		t.Fatal("expected Reject to be called")
	}
	if ch.reason != ssh.UnknownChannelType {
		t.Fatalf("reject reason = %v, want UnknownChannelType", ch.reason)
	}
	if len(log.calls) != 1 || log.calls[0].what != "random-thing" {
		t.Fatalf("reject log = %+v, want one random-thing entry", log.calls)
	}
}

func TestHandleGlobalRequest_RejectsTCPIPForward(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"tcpip-forward", "cancel-tcpip-forward"} {
		t.Run(name, func(t *testing.T) {
			req := &fakeRequest{t: name, wantReply: true}
			log := &recordingRejectLogger{}
			handleGlobalRequest(req, "1.2.3.4:5", log)
			if !req.deniedOnce {
				t.Fatal("expected Deny() to be called")
			}
			if len(log.calls) != 1 || log.calls[0].what != "tcpip" {
				t.Fatalf("reject log = %+v, want one tcpip entry", log.calls)
			}
		})
	}
}

func TestHandleGlobalRequest_SilentlyDeniesUnknown(t *testing.T) {
	t.Parallel()
	// Keepalives and other unknown global requests should be denied
	// without a reject-log entry — spec §9 only flags the documented
	// forwarding requests.
	req := &fakeRequest{t: "keepalive@openssh.com", wantReply: true}
	log := &recordingRejectLogger{}
	handleGlobalRequest(req, "1.2.3.4:5", log)
	if !req.deniedOnce {
		t.Fatal("expected Deny() to be called")
	}
	if len(log.calls) != 0 {
		t.Fatalf("unknown global request must not log reject; got %+v", log.calls)
	}
}

func TestSSHRequestAdapter_PassesThroughFields(t *testing.T) {
	t.Parallel()
	// Adapter mostly delegates, but the test pins the surface so a
	// future rename catches at compile/test time.
	a := sshRequestAdapter{r: &ssh.Request{Type: "tcpip-forward", WantReply: false}}
	if a.Reqtype() != "tcpip-forward" {
		t.Fatalf("Reqtype = %q, want tcpip-forward", a.Reqtype())
	}
	if a.WantsReply() {
		t.Fatal("WantsReply() = true, want false")
	}
	// Deny on a request with WantReply=false is a no-op and returns nil.
	if err := a.Deny(); err != nil {
		t.Fatalf("Deny on WantReply=false should be nil, got %v", err)
	}
}
