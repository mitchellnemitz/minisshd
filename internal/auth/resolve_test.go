package auth

import (
	"errors"
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
	// MINISSH_PASS="" with the flag absent is similarly rejected.
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
