package auth

import (
	"errors"
	"strings"
	"testing"
)

func TestResolvePassword_Precedence(t *testing.T) {
	cases := []struct {
		name      string
		flagPass  string
		envPass   string
		want      string
		wantEmpty bool
	}{
		{"flag wins over env", "flagpw", "envpw", "flagpw", false},
		{"flag wins when env empty", "flagpw", "", "flagpw", false},
		{"env used when no flag", "", "envpw", "envpw", false},
		{"neither set returns empty for generation", "", "", "", true},
		{"unicode flag value preserved", "日本語", "envpw", "日本語", false},
		{"long passphrase flag value preserved", "a very long passphrase with spaces", "", "a very long passphrase with spaces", false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got, err := ResolvePassword(tc.flagPass, tc.envPass)
			if err != nil {
				t.Fatalf("ResolvePassword(%q,%q) returned unexpected error: %v", tc.flagPass, tc.envPass, err)
			}
			if got != tc.want {
				t.Errorf("ResolvePassword(%q,%q) = %q, want %q", tc.flagPass, tc.envPass, got, tc.want)
			}
			if tc.wantEmpty && got != "" {
				t.Errorf("expected empty result when neither flag nor env set, got %q", got)
			}
		})
	}
}

func TestResolvePasswordStrict_RejectsExplicitEmpty(t *testing.T) {
	// `--pass=""` (flag supplied, value empty) must surface
	// ErrEmptyPassword per spec §2 step 2.
	if _, err := ResolvePasswordStrict("", true, "", false); !errors.Is(err, ErrEmptyPassword) {
		t.Errorf("strict resolve with empty flag: want ErrEmptyPassword, got %v", err)
	}
	// MINISSHD_PASS="" with the flag absent is similarly rejected.
	if _, err := ResolvePasswordStrict("", false, "", true); !errors.Is(err, ErrEmptyPassword) {
		t.Errorf("strict resolve with empty env: want ErrEmptyPassword, got %v", err)
	}
	// Both absent: ok, empty string with no error (caller generates).
	got, err := ResolvePasswordStrict("", false, "", false)
	if err != nil || got != "" {
		t.Errorf("strict resolve neither set: got (%q,%v), want (\"\",nil)", got, err)
	}
}

func TestResolvePasswordStrict_AcceptsNonEmptyValues(t *testing.T) {
	cases := []struct {
		name     string
		flagPass string
		flagSet  bool
		envPass  string
		envSet   bool
		want     string
	}{
		{"flag set non-empty wins", "hunter2", true, "envpw", true, "hunter2"},
		{"env used when flag unset", "", false, "envpw", true, "envpw"},
		{"unicode passphrase accepted", "日本語", true, "", false, "日本語"},
		{"long passphrase accepted", "a very long passphrase with spaces", true, "", false, "a very long passphrase with spaces"},
		{"numeric-only password accepted", "12345", true, "", false, "12345"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got, err := ResolvePasswordStrict(tc.flagPass, tc.flagSet, tc.envPass, tc.envSet)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestResolveUsername_Precedence(t *testing.T) {
	cases := []struct {
		name    string
		flag    string
		env     string
		osUser  string
		want    string
		wantErr error
	}{
		{"flag wins", "alice", "bob", "carol", "alice", nil},
		{"env wins over osUser", "", "bob", "carol", "bob", nil},
		{"osUser when nothing else", "", "", "carol", "carol", nil},
		{"empty everywhere returns error", "", "", "", "", ErrEmptyUsername},
		{"unicode username accepted", "日本語ユーザー", "", "", "日本語ユーザー", nil},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got, err := ResolveUsername(tc.flag, tc.env, tc.osUser)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("got err %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err %v", err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// TestResolveMethods_DefaultPassword verifies that when neither flag nor env
// is set, ResolveMethods returns Methods{"password"}.
func TestResolveMethods_DefaultPassword(t *testing.T) {
	got, err := ResolveMethods("", false, "", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0] != MethodPassword {
		t.Errorf("got %v, want [password]", got)
	}
}

// TestResolveMethods_FlagBeatsEnv verifies that when the flag is set, it wins
// over the env variable.
func TestResolveMethods_FlagBeatsEnv(t *testing.T) {
	got, err := ResolveMethods("publickey", true, "password", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0] != MethodPublickey {
		t.Errorf("got %v, want [publickey]", got)
	}
}

// TestResolveMethods_EnvUsedWhenFlagUnset verifies that the env var is used
// when the flag is not set.
func TestResolveMethods_EnvUsedWhenFlagUnset(t *testing.T) {
	got, err := ResolveMethods("", false, "password,publickey", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %v (len=%d), want 2 methods", got, len(got))
	}
	if !got.Contains(MethodPassword) || !got.Contains(MethodPublickey) {
		t.Errorf("got %v, want password and publickey", got)
	}
}

// TestResolveMethods_RejectsEmptyUnknownDuplicate covers the error cases.
func TestResolveMethods_RejectsEmptyUnknownDuplicate(t *testing.T) {
	cases := []struct {
		name    string
		flagVal string
		flagSet bool
		envVal  string
		envSet  bool
		wantErr error
	}{
		{"empty flag", "", true, "", false, ErrEmptyAuthMethods},
		{"empty env", "", false, "", true, ErrEmptyAuthMethods},
		{"unknown method", "ftp", true, "", false, ErrUnknownAuthMethod},
		{"duplicate method", "password,password", true, "", false, ErrDuplicateAuthMethod},
		{"comma-only", ",", true, "", false, ErrEmptyAuthMethods},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			_, err := ResolveMethods(tc.flagVal, tc.flagSet, tc.envVal, tc.envSet)
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("ResolveMethods(%q,%v,%q,%v) err = %v, want %v",
					tc.flagVal, tc.flagSet, tc.envVal, tc.envSet, err, tc.wantErr)
			}
		})
	}
}

// TestResolveAuthorizedKeysPath_XDG verifies that when XDG_CONFIG_HOME is set,
// the path uses XDG; when unset, it falls back to ~/.config/minisshd/authorized_keys.
func TestResolveAuthorizedKeysPath_XDG(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "/xdg/config")
	got, err := ResolveAuthorizedKeysPath("", false, "", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "/xdg/config/minisshd/authorized_keys"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}

	// When XDG_CONFIG_HOME is unset, fall back to HOME.
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", "/home/testuser")
	got, err = ResolveAuthorizedKeysPath("", false, "", false)
	if err != nil {
		t.Fatalf("unexpected error without XDG: %v", err)
	}
	if !strings.HasSuffix(got, ".config/minisshd/authorized_keys") {
		t.Errorf("fallback path %q should end with .config/minisshd/authorized_keys", got)
	}
}

// TestResolveAuthorizedKeysPath_FlagBeatsEnvBeatsXDG verifies the full
// precedence: flag > env > XDG.
func TestResolveAuthorizedKeysPath_FlagBeatsEnvBeatsXDG(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "/xdg")

	// Flag wins.
	got, err := ResolveAuthorizedKeysPath("/flag/keys", true, "/env/keys", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "/flag/keys" {
		t.Errorf("flag path: got %q, want /flag/keys", got)
	}

	// Env wins over XDG.
	got, err = ResolveAuthorizedKeysPath("", false, "/env/keys", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "/env/keys" {
		t.Errorf("env path: got %q, want /env/keys", got)
	}

	// XDG used when neither flag nor env set.
	got, err = ResolveAuthorizedKeysPath("", false, "", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(got, "/xdg/") {
		t.Errorf("XDG path: got %q, expected prefix /xdg/", got)
	}
}
