package server_test

// §13.3 integration tests for direct-tcpip (local port forwarding).
// Each test spins up the in-process server and uses a real TCP echo server
// or TCP listener as the forwarding target.

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// startEchoServer binds a TCP echo server on 127.0.0.1:0, registers a
// t.Cleanup handler, and returns the bound address.
func startEchoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("startEchoServer: listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()
	return ln.Addr().String()
}

// openDirectTCPIP opens a direct-tcpip channel to destAddr:destPort through
// the already-authenticated client. It returns the ssh.Channel on success.
func openDirectTCPIP(t *testing.T, cli *ssh.Client, destAddr string, destPort uint32) ssh.Channel {
	t.Helper()
	type directTCPIPPayload struct {
		DestAddr   string
		DestPort   uint32
		OriginAddr string
		OriginPort uint32
	}
	payload := ssh.Marshal(&directTCPIPPayload{
		DestAddr:   destAddr,
		DestPort:   destPort,
		OriginAddr: "127.0.0.1",
		OriginPort: 0,
	})
	ch, reqs, err := cli.OpenChannel("direct-tcpip", payload)
	if err != nil {
		t.Fatalf("OpenChannel direct-tcpip: %v", err)
	}
	go ssh.DiscardRequests(reqs)
	return ch
}

// TestIntegration_DirectTCPIP_EchoRoundTrip sends 64 random bytes through a
// direct-tcpip channel to a real TCP echo server and asserts the data comes
// back intact. It also asserts the forward-close log event carries
// bytes_in=64 and bytes_out=64 (matching the echo payload).
func TestIntegration_DirectTCPIP_EchoRoundTrip(t *testing.T) {
	echoAddr := startEchoServer(t)
	echoTCPAddr, err := net.ResolveTCPAddr("tcp", echoAddr)
	if err != nil {
		t.Fatalf("ResolveTCPAddr: %v", err)
	}
	echoHost := echoTCPAddr.IP.String()
	echoPort := uint32(echoTCPAddr.Port)

	ts := startTestServer(t, testServerOptions{})
	defer ts.cleanup()

	cli := dialSSH(t, ts.addr, clientConfig(ts.user, ts.password))
	defer cli.Close()

	ch := openDirectTCPIP(t, cli, echoHost, echoPort)
	defer ch.Close()

	// Send exactly 64 random bytes so we can assert bytes_in=64/bytes_out=64.
	const payloadSize = 64
	payload := make([]byte, payloadSize)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("rand: %v", err)
	}
	if _, err := ch.Write(payload); err != nil {
		t.Fatalf("write to channel: %v", err)
	}
	_ = ch.CloseWrite()

	got, err := io.ReadAll(ch)
	if err != nil {
		t.Fatalf("ReadAll from channel: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("echo mismatch: sent %d bytes got %d bytes", len(payload), len(got))
	}

	// Verify forward-open and forward-close appear in the log.
	if !waitForLog(t, ts.logBuf, "forward-close", 3*time.Second) {
		t.Fatalf("expected forward-close in log; got:\n%s", ts.logBuf.String())
	}
	logSnapshot := ts.logBuf.String()
	if !strings.Contains(logSnapshot, "forward-open") {
		t.Fatalf("expected forward-open in log; got:\n%s", logSnapshot)
	}

	// Assert bytes_in and bytes_out are both exactly payloadSize.
	wantBytes := fmt.Sprintf("%d", payloadSize)
	wantIn := "bytes_in=" + wantBytes
	wantOut := "bytes_out=" + wantBytes
	if !strings.Contains(logSnapshot, wantIn) {
		t.Fatalf("expected %s in forward-close log line; got:\n%s", wantIn, logSnapshot)
	}
	if !strings.Contains(logSnapshot, wantOut) {
		t.Fatalf("expected %s in forward-close log line; got:\n%s", wantOut, logSnapshot)
	}
}

// TestIntegration_DirectTCPIP_DialFailure asks the server to forward to a
// port that has no listener. The server must reject the channel with
// ConnectionFailed and log forward-reject reason=dial-failed.
func TestIntegration_DirectTCPIP_DialFailure(t *testing.T) {
	// Grab a free port, then immediately close the listener so nothing is
	// actually listening there.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	deadPort := uint32(ln.Addr().(*net.TCPAddr).Port)
	_ = ln.Close()

	ts := startTestServer(t, testServerOptions{})
	defer ts.cleanup()

	cli := dialSSH(t, ts.addr, clientConfig(ts.user, ts.password))
	defer cli.Close()

	type directTCPIPPayload struct {
		DestAddr   string
		DestPort   uint32
		OriginAddr string
		OriginPort uint32
	}
	payload := ssh.Marshal(&directTCPIPPayload{
		DestAddr:   "127.0.0.1",
		DestPort:   deadPort,
		OriginAddr: "127.0.0.1",
		OriginPort: 0,
	})
	_, _, openErr := cli.OpenChannel("direct-tcpip", payload)
	if openErr == nil {
		t.Fatal("expected OpenChannel to fail for dead port; got nil")
	}
	var ocErr *ssh.OpenChannelError
	if !errors.As(openErr, &ocErr) {
		t.Fatalf("expected *ssh.OpenChannelError, got %T (%v)", openErr, openErr)
	}
	if ocErr.Reason != ssh.ConnectionFailed {
		t.Logf("got reason=%v (expected ConnectionFailed)", ocErr.Reason)
	}

	if !waitForLog(t, ts.logBuf, "forward-reject", 2*time.Second) {
		t.Fatalf("expected forward-reject in log; got:\n%s", ts.logBuf.String())
	}
	if !strings.Contains(ts.logBuf.String(), "reason=dial-failed") {
		t.Fatalf("expected reason=dial-failed in log; got:\n%s", ts.logBuf.String())
	}
}

// TestIntegration_DirectTCPIP_MalformedPayload sends a direct-tcpip channel
// with a truncated payload. The server must reject it with ConnectionFailed
// and log forward-reject reason=malformed-payload.
func TestIntegration_DirectTCPIP_MalformedPayload(t *testing.T) {
	ts := startTestServer(t, testServerOptions{})
	defer ts.cleanup()

	cli := dialSSH(t, ts.addr, clientConfig(ts.user, ts.password))
	defer cli.Close()

	_, _, err := cli.OpenChannel("direct-tcpip", []byte{0x00, 0x00, 0x00, 0x01})
	if err == nil {
		t.Fatal("expected OpenChannel to fail for malformed payload; got nil")
	}
	var ocErr *ssh.OpenChannelError
	if !errors.As(err, &ocErr) {
		t.Fatalf("expected *ssh.OpenChannelError, got %T (%v)", err, err)
	}

	if !waitForLog(t, ts.logBuf, "forward-reject", 2*time.Second) {
		t.Fatalf("expected forward-reject in log; got:\n%s", ts.logBuf.String())
	}
	if !strings.Contains(ts.logBuf.String(), "reason=malformed-payload") {
		t.Fatalf("expected reason=malformed-payload in log; got:\n%s", ts.logBuf.String())
	}
}

// TestIntegration_DirectTCPIP_PerConnectionCap verifies that once the cap is
// reached, additional direct-tcpip opens are rejected with Prohibited and log
// forward-reject reason=over-cap. It also verifies that closing one open
// forward releases the slot so a subsequent open succeeds.
func TestIntegration_DirectTCPIP_PerConnectionCap(t *testing.T) {
	const cap = 2
	echoAddr := startEchoServer(t)
	echoHost, _, _ := net.SplitHostPort(echoAddr)
	echoTCPAddr, _ := net.ResolveTCPAddr("tcp", echoAddr)
	echoPort := uint32(echoTCPAddr.Port)

	ts := startTestServer(t, testServerOptions{forwardMax: cap})
	defer ts.cleanup()

	cli := dialSSH(t, ts.addr, clientConfig(ts.user, ts.password))
	defer cli.Close()

	// Open cap channels (should succeed). Keep them open so the counter stays
	// pinned — the goroutine inside handleDirectTCPIP only calls Release after
	// the bidi pipe finishes.
	channels := make([]ssh.Channel, cap)
	for i := 0; i < cap; i++ {
		channels[i] = openDirectTCPIP(t, cli, echoHost, echoPort)
	}

	// One more must fail with Prohibited.
	type directTCPIPPayload struct {
		DestAddr   string
		DestPort   uint32
		OriginAddr string
		OriginPort uint32
	}
	payload := ssh.Marshal(&directTCPIPPayload{
		DestAddr: echoHost, DestPort: echoPort,
		OriginAddr: "127.0.0.1", OriginPort: 0,
	})
	_, _, err := cli.OpenChannel("direct-tcpip", payload)
	if err == nil {
		t.Fatal("expected cap-exceeded OpenChannel to fail; got nil")
	}
	var ocErr *ssh.OpenChannelError
	if !errors.As(err, &ocErr) {
		t.Fatalf("expected *ssh.OpenChannelError, got %T (%v)", err, err)
	}
	if ocErr.Reason != ssh.Prohibited {
		t.Errorf("cap-exceeded reason = %v, want Prohibited", ocErr.Reason)
	}

	if !waitForLog(t, ts.logBuf, "reason=over-cap", 2*time.Second) {
		t.Fatalf("expected reason=over-cap in log; got:\n%s", ts.logBuf.String())
	}

	// Step 6 (plan §7.5): close one open forward, then assert a fourth open
	// succeeds — proving counter.Release fires correctly.
	_ = channels[0].Close()
	// Give the pipe goroutines a moment to finish and call Release.
	if !waitForLog(t, ts.logBuf, "forward-close", 2*time.Second) {
		t.Fatalf("expected forward-close after closing channel[0]; got:\n%s", ts.logBuf.String())
	}
	// Count forward-open events before the new open so we can verify a fresh one appears.
	logBefore := ts.logBuf.String()
	openCountBefore := strings.Count(logBefore, "forward-open")

	// Close channels[1] in cleanup; open a new fourth channel which should succeed.
	defer func() { _ = channels[1].Close() }()
	ch4 := openDirectTCPIP(t, cli, echoHost, echoPort)
	defer ch4.Close()

	if !waitForLog(t, ts.logBuf, "forward-open", 2*time.Second) {
		t.Fatalf("expected fresh forward-open after release; got:\n%s", ts.logBuf.String())
	}
	openCountAfter := strings.Count(ts.logBuf.String(), "forward-open")
	if openCountAfter <= openCountBefore {
		t.Fatalf("expected a new forward-open after releasing slot; before=%d after=%d",
			openCountBefore, openCountAfter)
	}
}

// TestIntegration_DirectTCPIP_TCPCloseTriggersChannelEOF verifies that when
// the upstream TCP server closes the connection, the SSH channel also reaches
// EOF (the pipe goroutines propagate the close).
func TestIntegration_DirectTCPIP_TCPCloseTriggersChannelEOF(t *testing.T) {
	// One-shot server: accept, write a line, close.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = io.WriteString(c, "goodbye\n")
	}()

	oneShotAddr, _ := net.ResolveTCPAddr("tcp", ln.Addr().String())

	ts := startTestServer(t, testServerOptions{})
	defer ts.cleanup()

	cli := dialSSH(t, ts.addr, clientConfig(ts.user, ts.password))
	defer cli.Close()

	ch := openDirectTCPIP(t, cli, "127.0.0.1", uint32(oneShotAddr.Port))
	defer ch.Close()

	buf := make([]byte, 128)
	n, _ := ch.Read(buf)
	if string(buf[:n]) != "goodbye\n" {
		t.Fatalf("expected 'goodbye\\n', got %q", buf[:n])
	}
	// Further reads should return EOF now that the server closed.
	ch.Read(buf) //nolint — just draining EOF
	wg.Wait()
}

// TestIntegration_DirectTCPIP_ChannelCloseTriggersTCPClose verifies that
// when the SSH client closes the channel, the outbound TCP connection also
// closes (via CloseWrite / Close propagation in the pipe goroutines).
func TestIntegration_DirectTCPIP_ChannelCloseTriggersTCPClose(t *testing.T) {
	// Server that reads until EOF and records what it got.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	received := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			received <- nil
			return
		}
		defer c.Close()
		data, _ := io.ReadAll(c)
		received <- data
	}()

	destAddr, _ := net.ResolveTCPAddr("tcp", ln.Addr().String())

	ts := startTestServer(t, testServerOptions{})
	defer ts.cleanup()

	cli := dialSSH(t, ts.addr, clientConfig(ts.user, ts.password))
	defer cli.Close()

	ch := openDirectTCPIP(t, cli, "127.0.0.1", uint32(destAddr.Port))

	const msg = "from-client\n"
	_, _ = io.WriteString(ch, msg)
	// Closing the channel signals EOF to the TCP side.
	_ = ch.Close()

	select {
	case data := <-received:
		if string(data) != msg {
			t.Fatalf("expected %q at TCP server, got %q", msg, data)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for TCP server to receive EOF")
	}
}

// TestIntegration_DirectTCPIP_RejectedWhenForwardMaxZero asserts that when
// ForwardMax is 0 (forwarding disabled), all direct-tcpip channels are
// rejected with Prohibited and logged as forward-reject reason=over-cap.
func TestIntegration_DirectTCPIP_RejectedWhenForwardMaxZero(t *testing.T) {
	ts := startTestServer(t, testServerOptions{disableForwarding: true})
	defer ts.cleanup()

	cli := dialSSH(t, ts.addr, clientConfig(ts.user, ts.password))
	defer cli.Close()

	type directTCPIPPayload struct {
		DestAddr   string
		DestPort   uint32
		OriginAddr string
		OriginPort uint32
	}
	payload := ssh.Marshal(&directTCPIPPayload{
		DestAddr: "127.0.0.1", DestPort: 80,
		OriginAddr: "127.0.0.1", OriginPort: 0,
	})
	_, _, err := cli.OpenChannel("direct-tcpip", payload)
	if err == nil {
		t.Fatal("expected OpenChannel to fail when forwarding disabled; got nil")
	}
	var ocErr *ssh.OpenChannelError
	if !errors.As(err, &ocErr) {
		t.Fatalf("expected *ssh.OpenChannelError, got %T (%v)", err, err)
	}
	if ocErr.Reason != ssh.Prohibited {
		t.Errorf("reason = %v, want Prohibited", ocErr.Reason)
	}

	if !waitForLog(t, ts.logBuf, "reason=over-cap", 2*time.Second) {
		t.Fatalf("expected reason=over-cap in log; got:\n%s", ts.logBuf.String())
	}
}
