package server

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
)

// directTCPIPPayload is the RFC 4254 §7.2 channel-open payload for
// "direct-tcpip". DestPort and OriginPort are uint32 on the wire even
// though the high half is meaningless for TCP — the parser enforces the
// [1, 65535] range for DestPort.
type directTCPIPPayload struct {
	DestAddr   string
	DestPort   uint32
	OriginAddr string
	OriginPort uint32
}

// dialTimeout is the §7.1 step-3 cap on the outbound TCP dial.
const dialTimeout = 10 * time.Second

// forwardLogger captures the three new §9 events that forward.go needs.
type forwardLogger interface {
	ForwardOpen(remote, destHost string, destPort int, origHost string, origPort int)
	ForwardClose(remote, destHost string, destPort int, bytesIn, bytesOut int64, duration time.Duration)
	ForwardReject(remote, destHost string, destPort int, reason string)
}

// forwardCounter is the per-connection "currently open forwards" counter
// the cap consults. handleConn instantiates one per accepted SSH connection
// as fwdCap (not forwardCounter — that is the type name); channel goroutines
// call Acquire/Release.
type forwardCounter struct {
	cap      int // <= 0 means forwarding disabled
	mu       sync.Mutex
	inflight int
}

// Acquire tries to claim one forwarding slot. Returns false when the cap
// is zero (forwarding disabled) or the cap has been reached.
func (c *forwardCounter) Acquire() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cap <= 0 || c.inflight >= c.cap {
		return false
	}
	c.inflight++
	return true
}

// Release returns one forwarding slot to the pool.
func (c *forwardCounter) Release() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.inflight > 0 {
		c.inflight--
	}
}

// parseDirectTCPIP parses the RFC 4254 §7.2 channel-open payload. Strict:
// rejects trailing bytes, dest-port == 0, and dest-port > 65535.
// originator-port is allowed to be 0 (some clients send 0 for ephemeral
// sockets).
func parseDirectTCPIP(data []byte) (directTCPIPPayload, error) {
	var p directTCPIPPayload
	if err := ssh.Unmarshal(data, &p); err != nil {
		return p, errors.New("malformed direct-tcpip payload: " + err.Error())
	}
	if p.DestPort == 0 || p.DestPort > 65535 {
		return p, errors.New("malformed direct-tcpip payload: dest-port out of range")
	}
	return p, nil
}

// dialDirect dials dest-host:dest-port via the context deadline (set to
// dialTimeout by the caller). We do NOT set Dialer.Timeout — relying solely
// on the context deadline avoids a redundant double-timeout.
func dialDirect(ctx context.Context, p directTCPIPPayload) (net.Conn, error) {
	addr := net.JoinHostPort(p.DestAddr, strconv.Itoa(int(p.DestPort)))
	d := net.Dialer{}
	return d.DialContext(ctx, "tcp", addr)
}

// handleDirectTCPIP is the entry point handleConn calls when classifyChannel
// returns actionForward. It owns the entire lifecycle of one direct-tcpip
// channel: payload parse → cap check → dial → Accept → bidi pipe → close.
func handleDirectTCPIP(
	ctx context.Context,
	newCh newChannelExt,
	remote string,
	counter *forwardCounter,
	log forwardLogger,
) {
	payload, err := parseDirectTCPIP(newCh.ExtraData())
	if err != nil {
		log.ForwardReject(remote, "", 0, "malformed-payload")
		_ = newCh.Reject(ssh.ConnectionFailed, "malformed direct-tcpip payload")
		return
	}

	destHost := payload.DestAddr
	destPort := int(payload.DestPort)

	if !counter.Acquire() {
		log.ForwardReject(remote, destHost, destPort, "over-cap")
		_ = newCh.Reject(ssh.Prohibited, "too many concurrent forwards")
		return
	}
	// Release happens after Accept fails, after dial fails, or after the
	// pipe goroutines complete — never twice.

	dialCtx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	tcp, err := dialDirect(dialCtx, payload)
	if err != nil {
		counter.Release()
		log.ForwardReject(remote, destHost, destPort, "dial-failed")
		_ = newCh.Reject(ssh.ConnectionFailed, "dial failed: "+err.Error())
		return
	}

	ch, reqs, err := newCh.Accept()
	if err != nil {
		counter.Release()
		_ = tcp.Close()
		return
	}
	go ssh.DiscardRequests(reqs)

	log.ForwardOpen(remote, destHost, destPort,
		payload.OriginAddr, int(payload.OriginPort))
	start := time.Now()

	var bytesIn, bytesOut atomic.Int64
	var wg sync.WaitGroup
	wg.Add(2)

	// channel → TCP (bytes flowing out of the SSH client into the destination)
	go func() {
		defer wg.Done()
		n, _ := io.Copy(tcp, ch)
		bytesOut.Store(n)
		if tw, ok := tcp.(interface{ CloseWrite() error }); ok {
			_ = tw.CloseWrite()
		} else {
			_ = tcp.Close()
		}
	}()

	// TCP → channel (bytes flowing from the destination back to the SSH client)
	go func() {
		defer wg.Done()
		n, _ := io.Copy(ch, tcp)
		bytesIn.Store(n)
		_ = ch.CloseWrite()
	}()

	wg.Wait()
	_ = ch.Close()
	_ = tcp.Close()
	counter.Release()
	log.ForwardClose(remote, destHost, destPort,
		bytesIn.Load(), bytesOut.Load(), time.Since(start))
}
