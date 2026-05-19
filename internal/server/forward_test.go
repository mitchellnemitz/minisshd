package server

import (
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
)

// buildDirectTCPIPPayload marshals a directTCPIPPayload into the wire bytes
// that parseDirectTCPIP expects.
func buildDirectTCPIPPayload(destAddr string, destPort uint32, origAddr string, origPort uint32) []byte {
	p := directTCPIPPayload{
		DestAddr:   destAddr,
		DestPort:   destPort,
		OriginAddr: origAddr,
		OriginPort: origPort,
	}
	return ssh.Marshal(&p)
}

func TestParseDirectTCPIP_OK(t *testing.T) {
	data := buildDirectTCPIPPayload("127.0.0.1", 80, "1.2.3.4", 12345)
	p, err := parseDirectTCPIP(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.DestAddr != "127.0.0.1" {
		t.Errorf("DestAddr = %q, want 127.0.0.1", p.DestAddr)
	}
	if p.DestPort != 80 {
		t.Errorf("DestPort = %d, want 80", p.DestPort)
	}
	if p.OriginAddr != "1.2.3.4" {
		t.Errorf("OriginAddr = %q, want 1.2.3.4", p.OriginAddr)
	}
	if p.OriginPort != 12345 {
		t.Errorf("OriginPort = %d, want 12345", p.OriginPort)
	}
}

func TestParseDirectTCPIP_OK_OriginPortZero(t *testing.T) {
	data := buildDirectTCPIPPayload("localhost", 443, "127.0.0.1", 0)
	_, err := parseDirectTCPIP(data)
	if err != nil {
		t.Fatalf("origin-port=0 should be accepted; got error: %v", err)
	}
}

func TestParseDirectTCPIP_MalformedTruncated(t *testing.T) {
	_, err := parseDirectTCPIP([]byte{0, 0, 0, 1})
	if err == nil {
		t.Fatal("expected error for truncated payload; got nil")
	}
}

func TestParseDirectTCPIP_MalformedTrailingGarbage(t *testing.T) {
	// Well-formed payload with one extra trailing byte. ssh.Unmarshal is
	// strict and rejects trailing bytes unconditionally.
	data := buildDirectTCPIPPayload("127.0.0.1", 80, "1.2.3.4", 12345)
	data = append(data, 0xFF)
	_, err := parseDirectTCPIP(data)
	if err == nil {
		t.Fatal("expected error for trailing-garbage payload; got nil")
	}
}

func TestParseDirectTCPIP_DestPortZero(t *testing.T) {
	data := buildDirectTCPIPPayload("127.0.0.1", 0, "1.2.3.4", 12345)
	_, err := parseDirectTCPIP(data)
	if err == nil {
		t.Fatal("expected error for dest-port=0; got nil")
	}
}

func TestParseDirectTCPIP_DestPortTooLarge(t *testing.T) {
	data := buildDirectTCPIPPayload("127.0.0.1", 70000, "1.2.3.4", 12345)
	_, err := parseDirectTCPIP(data)
	if err == nil {
		t.Fatal("expected error for dest-port=70000 (> 65535); got nil")
	}
}

func TestParseDirectTCPIP_EmptyDestHost(t *testing.T) {
	// An empty dest host is structurally valid per the parser (port
	// range is the only structural check after unmarshal). An empty
	// hostname will surface as a dial-failed when the connection is
	// attempted.
	data := buildDirectTCPIPPayload("", 80, "127.0.0.1", 12345)
	_, err := parseDirectTCPIP(data)
	if err != nil {
		t.Fatalf("empty dest host should be accepted by parser; got: %v", err)
	}
}

// forwardCounter unit tests

func TestForwardCounter_AcquireUntilCap(t *testing.T) {
	c := &forwardCounter{cap: 3}
	for i := 0; i < 3; i++ {
		if !c.Acquire() {
			t.Fatalf("Acquire %d: expected true, got false", i+1)
		}
	}
	if c.Acquire() {
		t.Fatal("fourth Acquire should have returned false (cap reached)")
	}
	c.Release()
	if !c.Acquire() {
		t.Fatal("Acquire after Release should succeed")
	}
}

func TestForwardCounter_CapZeroDisablesForwarding(t *testing.T) {
	c := &forwardCounter{cap: 0}
	if c.Acquire() {
		t.Fatal("Acquire with cap=0 should return false")
	}
}

func TestForwardCounter_NegativeCapTreatedAsZero(t *testing.T) {
	// Negative caps are rejected at startup, but the type allows them.
	// Acquire must return false defensively.
	c := &forwardCounter{cap: -5}
	if c.Acquire() {
		t.Fatal("Acquire with cap<0 should return false")
	}
}

func TestForwardCounter_RaceFreeUnderConcurrency(t *testing.T) {
	const cap = 10
	const goroutines = 1000
	c := &forwardCounter{cap: cap}

	var wg sync.WaitGroup
	var mu sync.Mutex
	maxSeen := 0

	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			if c.Acquire() {
				// Read inflight while holding the counter's own lock indirectly
				// via a separate check below. We just track it externally.
				mu.Lock()
				c.mu.Lock()
				if c.inflight > maxSeen {
					maxSeen = c.inflight
				}
				c.mu.Unlock()
				mu.Unlock()
				c.Release()
			}
		}()
	}
	wg.Wait()
	if maxSeen > cap {
		t.Fatalf("inflight exceeded cap: max=%d cap=%d", maxSeen, cap)
	}
}
