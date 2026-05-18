package server

import (
	"errors"
	"net"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/mitchellnemitz/minisshd/internal/auth"
	"github.com/mitchellnemitz/minisshd/internal/logging"
	"github.com/mitchellnemitz/minisshd/internal/ratelimit"
)

// rateLimiter is the narrow surface the password callback consumes from
// the rate-limit package. It is a package-private interface only so unit
// tests can substitute a deterministic stub; production code always wires
// the concrete *ratelimit.Limiter.
type rateLimiter interface {
	Acquire(ip net.IP) (time.Duration, func(success bool))
	Snapshot() map[string]int
}

// credentialChecker is the narrow surface the password callback consumes
// from the auth package. Same testability rationale as rateLimiter.
type credentialChecker interface {
	Check(user, password string) (bool, string)
}

// authLogger captures the auth-related logging methods so tests can
// observe what was logged without re-parsing logfmt output.
type authLogger interface {
	AuthOK(remote, user string)
	AuthFail(remote, user, reason string, attempt int, nextDelay time.Duration)
}

// sleeper abstracts time.Sleep so unit tests can verify the rate-limit
// delay was honored without burning wall-clock seconds.
type sleeper func(d time.Duration)

// errAuthFailed is the generic error returned to x/crypto/ssh when a
// password attempt fails. The library only needs a non-nil error to
// count the failure toward MaxAuthTries; the actual reason is logged by
// the callback, never reflected to the client.
var errAuthFailed = errors.New("password authentication failed")

// passwordCallback returns the ssh.ServerConfig.PasswordCallback wired
// to the given limiter, credentials, logger, and sleeper. Per spec §5
// the lifecycle is strictly:
//
//  1. Acquire the per-IP slot (returns the delay the caller must sleep).
//  2. Sleep that delay (blocking the callback, not the accept loop).
//  3. Check the presented credentials against the cached digests.
//  4. release(ok) — feeds the result back into the limiter.
//  5. Log auth-ok on success, or auth-fail with the right reason on
//     failure. The attempt/next_delay fields come from the limiter
//     snapshot taken immediately after release(false).
func passwordCallback(
	lim rateLimiter,
	creds credentialChecker,
	log authLogger,
	sleep sleeper,
) func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
	return func(meta ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		remote := meta.RemoteAddr().String()
		ip := extractIP(meta.RemoteAddr())

		delay, release := lim.Acquire(ip)
		sleep(delay)
		ok, reason := creds.Check(meta.User(), string(password))
		release(ok)

		if ok {
			log.AuthOK(remote, meta.User())
			return &ssh.Permissions{}, nil
		}

		// On failure, the just-recorded failure has incremented the
		// counter. Read the snapshot under the normalized key so the
		// logged attempt count matches the limiter's view. A concurrent
		// successful auth from the same IP could have wiped the entry
		// out from under us; treat missing as 0 and fall back to
		// computeDelay-equivalent semantics (next_delay = 0).
		key := normalizeKey(ip)
		snapshot := lim.Snapshot()
		attempt := snapshot[key]
		next := nextDelay(attempt)

		log.AuthFail(remote, meta.User(), reason, attempt, next)
		return nil, errAuthFailed
	}
}

// extractIP pulls the IP out of a net.Addr. The SSH server always sees a
// *net.TCPAddr (the listener accepts TCP); other shapes are defensive
// fallbacks. Normalization (::ffff:x.x.x.x → x.x.x.x) is handled inside
// the limiter, so we pass the raw IP through.
func extractIP(addr net.Addr) net.IP {
	switch a := addr.(type) {
	case *net.TCPAddr:
		return a.IP
	case *net.UDPAddr:
		return a.IP
	case *net.IPAddr:
		return a.IP
	}
	// Last-resort: parse the host portion of the textual address.
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		host = addr.String()
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip
	}
	return nil
}

// normalizeKey mirrors the limiter's normalization so we can look up the
// just-released entry in Snapshot(). IPv4-mapped IPv6 collapses to bare
// IPv4 (matches ratelimit.normalize).
func normalizeKey(ip net.IP) string {
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}

// nextDelay reports the sleep the next attempt from this IP would incur
// given the supplied fail_count. It must agree with the limiter's
// internal computeDelay; the formula is small enough to duplicate in
// place rather than expose. Spec §5 sequence over rising fail_count is
// 1s, 2s, 4s, 8s, 16s, 32s, 60s, 60s, …
func nextDelay(failCount int) time.Duration {
	if failCount <= 0 {
		return 0
	}
	exp := failCount - 1
	if exp > 62 {
		return ratelimit.MaxDelay
	}
	d := time.Duration(int64(1)<<exp) * time.Second
	if d > ratelimit.MaxDelay || d < 0 {
		return ratelimit.MaxDelay
	}
	return d
}

// Static type-checks: the concrete dependencies must satisfy the
// package-private interfaces we wire through. If a future refactor
// renames a method, the compiler catches it here rather than in a
// distant call site.
var (
	_ rateLimiter       = (*ratelimit.Limiter)(nil)
	_ credentialChecker = (*auth.Credentials)(nil)
	_ authLogger        = (*logging.Logger)(nil)
)
