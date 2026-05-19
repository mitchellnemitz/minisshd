package auth

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"os"
	"sort"
	"sync/atomic"

	"golang.org/x/crypto/ssh"
)

// pubkeyLogger is the narrow logging interface consumed by KeysetSource.
// It is satisfied by *logging.Logger (asserted in internal/server/auth.go).
type pubkeyLogger interface {
	PubkeyParseError(path string, line int, errMsg string)
	PubkeyOptionIgnored(path string, line int, option string)
	PubkeyKeysMissing(path string)
	PubkeyReloadOK(path string, pubkeyCount int)
	PubkeyReloadFailed(path string, errMsg string)
}

// ReasonBadKey is the reason code returned when the presented public key
// does not match any accepted key.
const ReasonBadKey = "bad-key"

// AcceptedKey holds a parsed authorized-keys entry together with its
// pre-computed SHA-256 digest (over the wire-format Marshal bytes) and
// the SSH fingerprint string.
type AcceptedKey struct {
	Marshal     []byte
	Digest      [sha256.Size]byte
	Fingerprint string
	Comment     string
}

// Keyset is an immutable snapshot of the accepted public keys. It is safe for
// concurrent reads; updates are performed by atomically swapping the pointer
// held in KeysetSource.
type Keyset struct {
	keys []AcceptedKey
}

// Count returns the number of accepted keys in the keyset.
func (ks *Keyset) Count() int {
	if ks == nil {
		return 0
	}
	return len(ks.keys)
}

// Check compares the presented public key against every accepted key using
// SHA-256 digests and subtle.ConstantTimeCompare. The iteration is
// non-short-circuiting: the entire keyset is always scanned.
//
// Returns (ok, reason, fingerprint) where fingerprint is always the
// SHA-256 fingerprint of the presented key (useful for logging failures).
func (ks *Keyset) Check(presentedKey ssh.PublicKey) (ok bool, reason string, fp string) {
	presented := sha256.Sum256(presentedKey.Marshal())
	fp = ssh.FingerprintSHA256(presentedKey)

	var matched int
	if ks == nil || len(ks.keys) == 0 {
		// Empty keyset: run one dummy compare so the timing floor matches
		// "one configured key", then explicitly discard the result.
		var zero [sha256.Size]byte
		_ = subtle.ConstantTimeCompare(presented[:], zero[:])
		matched = 0 // dummy compare result discarded; empty keyset never authenticates
	} else {
		for _, k := range ks.keys {
			matched |= subtle.ConstantTimeCompare(presented[:], k.Digest[:])
		}
	}

	if matched != 0 {
		return true, "", fp
	}
	return false, ReasonBadKey, fp
}

// KeysetSource owns an authorized-keys file path and an atomic pointer to
// the current Keyset. It provides Load (initial load) and Reload (SIGHUP).
type KeysetSource struct {
	path string
	log  pubkeyLogger
	cur  atomic.Pointer[Keyset]
}

// NewKeysetSource constructs a KeysetSource for the given file path and logger.
// Load must be called before the source is used.
func NewKeysetSource(path string, log pubkeyLogger) *KeysetSource {
	return &KeysetSource{path: path, log: log}
}

// Current returns the current keyset. May return nil if Load has not been
// called yet or the initial load failed.
func (s *KeysetSource) Current() *Keyset {
	return s.cur.Load()
}

// Count returns the number of accepted keys in the current keyset.
func (s *KeysetSource) Count() int {
	ks := s.cur.Load()
	if ks == nil {
		return 0
	}
	return ks.Count()
}

// Load parses the authorized-keys file and atomically stores the resulting
// Keyset. os.ErrNotExist is treated as an empty keyset (with a warning log);
// other open errors are returned to the caller.
func (s *KeysetSource) Load() error {
	ks, err := s.parse()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			s.log.PubkeyKeysMissing(s.path)
			empty := &Keyset{}
			s.cur.Store(empty)
			return nil
		}
		return err
	}
	s.cur.Store(ks)
	return nil
}

// Reload re-parses the file and atomically swaps the current keyset.
// On failure (open error, or zero usable keys when the current keyset had ≥1),
// the previous keyset is preserved and pubkey-reload-failed is logged.
func (s *KeysetSource) Reload() error {
	ks, err := s.parse()
	if err != nil {
		s.log.PubkeyReloadFailed(s.path, err.Error())
		return err
	}
	// If the new keyset has zero keys but the current one had ≥1 key,
	// treat as failure to prevent accidental empty-file rotation from
	// locking out all publickey clients.
	prev := s.cur.Load()
	if ks.Count() == 0 && prev != nil && prev.Count() >= 1 {
		s.log.PubkeyReloadFailed(s.path, "reload yielded zero usable keys; preserving previous keyset")
		return fmt.Errorf("reload yielded zero usable keys")
	}
	s.cur.Store(ks)
	s.log.PubkeyReloadOK(s.path, ks.Count())
	return nil
}

// parse reads and parses the authorized-keys file, returning an immutable
// Keyset. It logs per-line warnings for malformed lines and option-bearing
// lines. Returns os.ErrNotExist (wrapped) if the file is missing, or the
// underlying os.Open error for other failures.
func (s *KeysetSource) parse() (*Keyset, error) {
	f, err := os.Open(s.path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var accepted []AcceptedKey
	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// Skip blank lines and comments.
		trimmed := bytes.TrimSpace([]byte(line))
		if len(trimmed) == 0 || trimmed[0] == '#' {
			continue
		}

		pubKey, comment, opts, rest, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			s.log.PubkeyParseError(s.path, lineNum, err.Error())
			continue
		}
		// rest should be empty for a well-formed line (ParseAuthorizedKey
		// returns what follows the key; a trailing comment is part of comment).
		_ = rest

		// Log a warning for any key options.
		if len(opts) > 0 {
			// opts is []string; emit once per options-bearing line using the
			// first option as the representative value.
			s.log.PubkeyOptionIgnored(s.path, lineNum, opts[0])
		}

		raw := pubKey.Marshal()
		digest := sha256.Sum256(raw)
		accepted = append(accepted, AcceptedKey{
			Marshal:     raw,
			Digest:      digest,
			Fingerprint: ssh.FingerprintSHA256(pubKey),
			Comment:     comment,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	// Sort digests lexicographically so reload-induced reordering does not
	// change the iteration pattern.
	sort.Slice(accepted, func(i, j int) bool {
		return bytes.Compare(accepted[i].Digest[:], accepted[j].Digest[:]) < 0
	})

	return &Keyset{keys: accepted}, nil
}
