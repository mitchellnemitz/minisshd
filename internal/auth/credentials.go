package auth

import (
	"crypto/sha256"
	"crypto/subtle"
)

// Reason codes returned by Credentials.Check. The empty string indicates
// success; any non-empty value indicates auth failed and identifies which
// component the logger should record in the auth-fail event (§9).
const (
	ReasonBadUser     = "bad-user"
	ReasonBadPassword = "bad-password"
)

// Credentials caches SHA-256 digests of the configured username and
// password. Per spec §4 the digests are computed once at startup (after
// the password is finalized in §2 step 2 or step 8) and reused on every
// auth callback. Hashing equal-length inputs lets the subsequent
// subtle.ConstantTimeCompare run on guaranteed-equal byte slices, which
// is the precondition for its constant-time guarantee.
//
// The struct itself is immutable after construction so it is safe to share
// across goroutines without synchronization.
type Credentials struct {
	userHash     [sha256.Size]byte
	passwordHash [sha256.Size]byte
}

// NewCredentials computes and caches the SHA-256 digests of the
// configured username and password.
func NewCredentials(user, password string) *Credentials {
	return &Credentials{
		userHash:     sha256.Sum256([]byte(user)),
		passwordHash: sha256.Sum256([]byte(password)),
	}
}

// Check compares presented credentials against the cached digests with
// constant-time primitives. Both comparisons always run — there is no
// early return between them — and the results are combined with a
// bitwise AND on subtle.ConstantTimeCompare's int return value to avoid
// short-circuiting via the Go `&&` operator. See spec §4.
//
// The reason string encodes which side failed:
//
//   - "" when both match (ok=true).
//   - ReasonBadUser when the username mismatched. This also wins when
//     both username and password mismatched, per §4 step 3 "user wins for
//     logging".
//   - ReasonBadPassword when only the password mismatched.
//
// IMPORTANT: do not refactor this function to introduce branches between
// the two ConstantTimeCompare calls. The test suite asserts both calls
// always run via a wrapper-injected counter. Spec §4 step 2 calls this
// out explicitly.
func (c *Credentials) Check(presentedUser, presentedPassword string) (ok bool, reason string) {
	return c.checkWith(presentedUser, presentedPassword, constantTimeCompare)
}

// constantTimeCompare is the production implementation used by Check; it
// is swapped out in tests via checkWith to count invocations and assert
// no short-circuiting occurs.
func constantTimeCompare(a, b []byte) int {
	return subtle.ConstantTimeCompare(a, b)
}

// checkWith is the underlying implementation seam. Production code calls
// Check, which threads in subtle.ConstantTimeCompare; tests substitute a
// counting wrapper to prove both comparisons always run.
func (c *Credentials) checkWith(presentedUser, presentedPassword string, cmp func(a, b []byte) int) (bool, string) {
	presentedUserHash := sha256.Sum256([]byte(presentedUser))
	presentedPasswordHash := sha256.Sum256([]byte(presentedPassword))

	// Both calls always run. The intermediate variables prevent the
	// compiler from short-circuiting, and the final combine uses a
	// bitwise AND on the int returns rather than `&&` on bools.
	userMatch := cmp(presentedUserHash[:], c.userHash[:])
	passMatch := cmp(presentedPasswordHash[:], c.passwordHash[:])

	okInt := userMatch & passMatch
	if okInt == 1 {
		return true, ""
	}
	// Failure path. Spec §4 step 3: user wins for logging when both are
	// wrong, so we check the user side first.
	if userMatch == 0 {
		return false, ReasonBadUser
	}
	return false, ReasonBadPassword
}
