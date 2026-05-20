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
	CheckUsername(user string) (bool, string)
}

// publickeyChecker is the narrow surface the publickey callback consumes
// from the auth package. It returns the current Keyset for each invocation.
type publickeyChecker interface {
	Current() *auth.Keyset
}

// authLogger captures the auth-related logging methods so tests can
// observe what was logged without re-parsing logfmt output.
// method is "password" or "publickey"; fingerprint is the SHA-256 fingerprint
// for publickey auth, or empty for password auth.
type authLogger interface {
	AuthOK(remote, user, method, fingerprint string)
	AuthFail(remote, user, method, reason string, attempt int, nextDelay time.Duration, fingerprint string)
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
			log.AuthOK(remote, meta.User(), "password", "")
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

		log.AuthFail(remote, meta.User(), "password", reason, attempt, next, "")
		return nil, errAuthFailed
	}
}

// publickeyCallback returns the ssh.ServerConfig.PublicKeyCallback wired to
// the given limiter, credentials, keyset source, logger, and sleeper.
//
// Library semantics (authoritative, verified against v0.51.0 source):
// golang.org/x/crypto/ssh calls PublicKeyCallback unconditionally on the
// first encounter of a (user, key) pair per connection — regardless of
// whether the client is probing (isQuery=true, no signature attached) or
// presenting a real signature (isQuery=false). The library uses a size-1
// cache (maxCachedPubKeys=1, ssh/server.go: pubKeyCache) to avoid calling
// the callback twice for the common probe-then-sign sequence with the same
// key. The callback has no way to distinguish a query from a real signature;
// it fires on first encounter and its result is cached for the subsequent
// signature attempt.
//
// Rate-limiter design: lim.Acquire runs for every first-seen (user, key) pair,
// including probe-only keys the client never signs with. This is a deliberate,
// tighter-than-OpenSSH posture: OpenSSH does not rate-limit per query;
// minisshd does. The benefit is that an attacker probing large key sets incurs
// backoff immediately, before presenting a signature.
func publickeyCallback(
	lim rateLimiter,
	creds credentialChecker,
	source publickeyChecker,
	log authLogger,
	sleep sleeper,
) func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
	return func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		remote := meta.RemoteAddr().String()
		ip := extractIP(meta.RemoteAddr())

		delay, release := lim.Acquire(ip)
		sleep(delay)

		// Both calls always run; results are pre-materialized before &&.
		userOK, userReason := creds.CheckUsername(meta.User())
		keyOK, keyReason, fp := source.Current().Check(key)

		ok := userOK && keyOK
		release(ok)

		if ok {
			log.AuthOK(remote, meta.User(), "publickey", fp)
			return &ssh.Permissions{}, nil
		}

		// Reason precedence: bad-user wins over bad-key (mirrors password path).
		reason := keyReason
		if !userOK {
			reason = userReason
		}

		key2 := normalizeKey(ip)
		snapshot := lim.Snapshot()
		attempt := snapshot[key2]
		next := nextDelay(attempt)

		log.AuthFail(remote, meta.User(), "publickey", reason, attempt, next, fp)
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

// pubkeyLogger is the narrow logging interface satisfied by *logging.Logger
// that covers the pubkey-* event methods. It mirrors the unexported interface
// in internal/auth/pubkey.go; both must stay in sync.
type pubkeyLogger interface {
	PubkeyParseError(path string, line int, errMsg string)
	PubkeyOptionIgnored(path string, line int, option string)
	PubkeyKeysMissing(path string)
	PubkeyReloadOK(path string, pubkeyCount int)
	PubkeyReloadFailed(path string, errMsg string)
}

// Static type-checks: the concrete dependencies must satisfy the
// package-private interfaces we wire through. If a future refactor
// renames a method, the compiler catches it here rather than in a
// distant call site.
var (
	_ rateLimiter       = (*ratelimit.Limiter)(nil)
	_ credentialChecker = (*auth.Credentials)(nil)
	_ authLogger        = (*logging.Logger)(nil)
	_ publickeyChecker  = (*auth.KeysetSource)(nil)
	_ pubkeyLogger      = (*logging.Logger)(nil)
)
