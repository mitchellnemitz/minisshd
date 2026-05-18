package auth

import (
	"crypto/subtle"
	"testing"
	"time"
)

func TestCredentials_Check_AllFourCombinations(t *testing.T) {
	creds := NewCredentials("alice", "hunter2")

	cases := []struct {
		name       string
		user, pass string
		wantOK     bool
		wantReason string
	}{
		{"good user + good pass", "alice", "hunter2", true, ""},
		{"bad user + good pass", "mallory", "hunter2", false, ReasonBadUser},
		{"good user + bad pass", "alice", "wrong", false, ReasonBadPassword},
		{"bad user + bad pass (user wins)", "mallory", "wrong", false, ReasonBadUser},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			ok, reason := creds.Check(tc.user, tc.pass)
			if ok != tc.wantOK || reason != tc.wantReason {
				t.Errorf("Check(%q,%q) = (%v,%q), want (%v,%q)",
					tc.user, tc.pass, ok, reason, tc.wantOK, tc.wantReason)
			}
		})
	}
}

func TestCredentials_Check_NonEmptyConfiguredCredentials(t *testing.T) {
	// Unicode and long-passphrase acceptance: building Credentials with
	// these values, then verifying with them, must succeed; verifying
	// with anything else must fail with the expected reason.
	cases := []struct {
		name string
		user string
		pass string
	}{
		{"unicode password", "alice", "日本語"},
		{"long passphrase", "alice", "a very long passphrase with spaces"},
		{"numeric six-digit", "alice", "482910"},
		{"unicode username", "日本語ユーザー", "hunter2"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			c := NewCredentials(tc.user, tc.pass)
			ok, reason := c.Check(tc.user, tc.pass)
			if !ok || reason != "" {
				t.Errorf("Check on matching creds = (%v,%q), want (true,\"\")", ok, reason)
			}
			ok, reason = c.Check(tc.user, tc.pass+"x")
			if ok || reason != ReasonBadPassword {
				t.Errorf("Check with bad pass = (%v,%q), want (false,bad-password)", ok, reason)
			}
		})
	}
}

// TestCredentials_Check_NoShortCircuit proves the implementation always
// runs both subtle.ConstantTimeCompare calls regardless of which input
// is wrong. It uses checkWith with a wrapper that counts invocations,
// then asserts the count is 2 across all four input combinations.
func TestCredentials_Check_NoShortCircuit(t *testing.T) {
	c := NewCredentials("alice", "hunter2")
	cases := []struct {
		name       string
		user, pass string
	}{
		{"both correct", "alice", "hunter2"},
		{"wrong user", "mallory", "hunter2"},
		{"wrong pass", "alice", "wrong"},
		{"both wrong", "mallory", "wrong"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			var calls int
			counting := func(a, b []byte) int {
				calls++
				return subtle.ConstantTimeCompare(a, b)
			}
			c.checkWith(tc.user, tc.pass, counting)
			if calls != 2 {
				t.Errorf("expected 2 ConstantTimeCompare calls, got %d", calls)
			}
		})
	}
}

// TestCredentials_Check_TimingEnvelope is a loose timing assertion that
// wrong-user and wrong-password paths complete within the same envelope.
// The strict statistical Mann-Whitney test described in spec §13.2 lives
// in a later layer; this one just guards against an O(N) regression
// like an accidental strings.Compare being re-introduced.
//
// We run each case enough times to amortize noise and assert the mean of
// each path is within 5x of the other. A real timing leak would show
// orders of magnitude difference, not 5x.
func TestCredentials_Check_TimingEnvelope(t *testing.T) {
	if testing.Short() {
		t.Skip("loose timing assertion; skipped under -short")
	}
	c := NewCredentials("alice", "hunter2")
	const iters = 2000
	measure := func(user, pass string) time.Duration {
		// warmup
		for i := 0; i < 200; i++ {
			c.Check(user, pass)
		}
		start := time.Now()
		for i := 0; i < iters; i++ {
			c.Check(user, pass)
		}
		return time.Since(start)
	}
	badUser := measure("mallory", "hunter2")
	badPass := measure("alice", "wrong")
	ratio := float64(badUser) / float64(badPass)
	if ratio < 0.2 || ratio > 5.0 {
		t.Errorf("timing envelope too wide: bad-user=%v bad-pass=%v ratio=%.2f", badUser, badPass, ratio)
	}
}
