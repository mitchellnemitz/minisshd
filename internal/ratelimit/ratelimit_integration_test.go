package ratelimit_test

import "testing"

// Integration tests for the rate limiter drive the in-process server with a
// real clock so cross-connection backoff is observable end-to-end. Scenarios
// enumerated from spec §13.3; real bodies arrive in phase 4.

// TestIntegration_BackoffAcrossReconnects is the slow ~16 s timing test from
// spec §13.3/§13.6: five sequential failed connections from one IP, then a
// sixth with correct credentials whose auth-ok must land in [13 s, 21 s] from
// the start of the sixth TCP handshake. It is gated by testing.Short() so the
// fast `make test` target stays under 10 s.
func TestIntegration_BackoffAcrossReconnects(t *testing.T) {
	if testing.Short() {
		t.Skip("slow ~16 s backoff timing test; skipped under -short")
	}
	t.Skip("not yet implemented — phase 4")
}

func TestIntegration_SuccessfulAuthResetsBackoffCounter(t *testing.T) {
	t.Skip("not yet implemented — phase 4")
}

func TestIntegration_IPv4MappedIPv6NormalizationSharesCounter(t *testing.T) {
	t.Skip("not yet implemented — phase 4")
}
