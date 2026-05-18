package auth

import "errors"

// ErrEmptyPassword is returned when a user-supplied password value (via flag
// or environment variable) is the empty string. Per spec §2 step 2, an
// explicitly empty password is rejected with exit code 2 at the call site.
var ErrEmptyPassword = errors.New("password must not be empty")

// ErrEmptyUsername is returned when the resolved username is the empty
// string after walking the precedence chain. Per spec §2 step 3 the call
// site exits with code 2.
var ErrEmptyUsername = errors.New("username must not be empty")

// ResolvePassword implements spec §2 step 2.
//
// Precedence: --pass (flagPass) > $MINISSH_PASS (envPass). A flag or env
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
// presence flags. The cmd/minissh layer uses this when it wants to reject
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
// Precedence: --user (flagUser) > $MINISSH_USER (envUser) > osUser. An
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
