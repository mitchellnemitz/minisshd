package auth

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ErrEmptyPassword is returned when a user-supplied password value (via flag
// or environment variable) is the empty string. Per spec §2 step 2, an
// explicitly empty password is rejected with exit code 2 at the call site.
var ErrEmptyPassword = errors.New("password must not be empty")

// ErrEmptyAuthMethods is returned when the resolved auth methods string is
// empty (after trimming). Per spec §2 step 2b, exit code 2 at the call site.
var ErrEmptyAuthMethods = errors.New("auth methods must not be empty")

// ErrUnknownAuthMethod is returned when a method token is not "password" or
// "publickey". Wrap with fmt.Errorf to include the bad token.
var ErrUnknownAuthMethod = errors.New("unknown auth method")

// ErrDuplicateAuthMethod is returned when the same method appears twice.
// Wrap with fmt.Errorf to include the duplicate token.
var ErrDuplicateAuthMethod = errors.New("duplicate auth method")

// Method name constants matching golang.org/x/crypto/ssh protocol identifiers.
// Names are case-sensitive.
const (
	MethodPassword  = "password"
	MethodPublickey = "publickey"
)

// Methods is an ordered list of SSH auth method names. Order is preserved from
// the input string and surfaces in the SSH methods list returned to clients.
type Methods []string

// Contains reports whether the named method is in the list.
func (m Methods) Contains(method string) bool {
	for _, v := range m {
		if v == method {
			return true
		}
	}
	return false
}

// String returns the methods joined by commas in original order.
func (m Methods) String() string {
	return strings.Join(m, ",")
}

// Names returns the methods as a plain []string slice.
func (m Methods) Names() []string {
	return []string(m)
}

// ResolveMethods implements spec §2 step 2b. It parses the comma-separated
// auth method string from --auth or MINISSHD_AUTH.
//
// Precedence: flag-set > env-set > default ("password").
// Returns ErrEmptyAuthMethods, ErrUnknownAuthMethod, or ErrDuplicateAuthMethod
// on invalid input.
func ResolveMethods(flagVal string, flagSet bool, envVal string, envSet bool) (Methods, error) {
	raw := ""
	if flagSet {
		raw = flagVal
	} else if envSet {
		raw = envVal
	} else {
		return Methods{MethodPassword}, nil
	}

	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, ErrEmptyAuthMethods
	}

	tokens := strings.Split(raw, ",")
	seen := make(map[string]bool, len(tokens))
	methods := make(Methods, 0, len(tokens))
	for _, tok := range tokens {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			return nil, ErrEmptyAuthMethods
		}
		if tok != MethodPassword && tok != MethodPublickey {
			return nil, fmt.Errorf("%w %q", ErrUnknownAuthMethod, tok)
		}
		if seen[tok] {
			return nil, fmt.Errorf("%w %q", ErrDuplicateAuthMethod, tok)
		}
		seen[tok] = true
		methods = append(methods, tok)
	}
	return methods, nil
}

// ResolveAuthorizedKeysPath resolves the authorized-keys file path per spec
// §2 step 2c. Precedence: flag-set > env-set > XDG_CONFIG_HOME >
// ~/.config/minisshd/authorized_keys.
func ResolveAuthorizedKeysPath(flagVal string, flagSet bool, envVal string, envSet bool) (string, error) {
	if flagSet && flagVal != "" {
		return flagVal, nil
	}
	if envSet && envVal != "" {
		return envVal, nil
	}
	// XDG fallback.
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "minisshd", "authorized_keys"), nil
	}
	hd, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot resolve home directory: %w", err)
	}
	return filepath.Join(hd, ".config", "minisshd", "authorized_keys"), nil
}

// ErrEmptyUsername is returned when the resolved username is the empty
// string after walking the precedence chain. Per spec §2 step 3 the call
// site exits with code 2.
var ErrEmptyUsername = errors.New("username must not be empty")

// ResolvePassword implements spec §2 step 2.
//
// Precedence: --pass (flagPass) > $MINISSHD_PASS (envPass). A flag or env
// value that is the empty string is treated as "supplied but empty" and
// returns ErrEmptyPassword — the caller must not auto-generate. If neither
// the flag nor the env var is set the function returns ("", nil) and the
// caller is expected to generate a random password (spec §2 step 8).
//
// The caller is responsible for distinguishing "flag not set" from "flag
// set to empty string"; we treat any non-empty argument as supplied and
// any empty argument as not-supplied at this layer because Go's flag
// package collapses the two cases. The integration with the flag library
// must therefore detect explicit empty flags separately if it wants to
// reject `--pass=""`; for the env var an unset variable and an empty
// variable look the same, which matches the spec.
func ResolvePassword(flagPass, envPass string) (string, error) {
	if flagPass != "" {
		return flagPass, nil
	}
	if envPass != "" {
		return envPass, nil
	}
	// Neither set: caller will generate. The spec's "empty-password
	// rejection" rule only fires when the user explicitly supplied an
	// empty value; nothing supplied is fine.
	return "", nil
}

// ResolvePasswordStrict is like ResolvePassword but distinguishes "flag
// supplied as empty string" from "flag not supplied" via explicit boolean
// presence flags. The cmd/minisshd layer uses this when it wants to reject
// `--pass=""` per spec §2 step 2.
func ResolvePasswordStrict(flagPass string, flagSet bool, envPass string, envSet bool) (string, error) {
	if flagSet {
		if flagPass == "" {
			return "", ErrEmptyPassword
		}
		return flagPass, nil
	}
	if envSet {
		if envPass == "" {
			return "", ErrEmptyPassword
		}
		return envPass, nil
	}
	return "", nil
}

// ResolveUsername implements spec §2 step 3.
//
// Precedence: --user (flagUser) > $MINISSHD_USER (envUser) > osUser. An
// empty resolved username is an error. The caller is expected to pass the
// OS user (e.g. $USER, or getpwuid(getuid()).Username) as the third
// argument; an empty osUser combined with empty flag and env values yields
// ErrEmptyUsername.
func ResolveUsername(flagUser, envUser, osUser string) (string, error) {
	if flagUser != "" {
		return flagUser, nil
	}
	if envUser != "" {
		return envUser, nil
	}
	if osUser != "" {
		return osUser, nil
	}
	return "", ErrEmptyUsername
}
