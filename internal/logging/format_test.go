package logging

import (
	"strings"
	"testing"
)

func TestParseFormat_Default(t *testing.T) {
	t.Parallel()
	f, err := ParseFormat("", false, "", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f != FormatLogfmt {
		t.Errorf("got %v, want FormatLogfmt", f)
	}
}

func TestParseFormat_FlagWins(t *testing.T) {
	t.Parallel()
	// Flag=json, env=logfmt — flag takes precedence.
	f, err := ParseFormat("json", true, "logfmt", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f != FormatJSON {
		t.Errorf("got %v, want FormatJSON", f)
	}
}

func TestParseFormat_EnvUsedWhenFlagUnset(t *testing.T) {
	t.Parallel()
	f, err := ParseFormat("", false, "json", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f != FormatJSON {
		t.Errorf("got %v, want FormatJSON", f)
	}
}

func TestParseFormat_LogfmtFlag(t *testing.T) {
	t.Parallel()
	f, err := ParseFormat("logfmt", true, "", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f != FormatLogfmt {
		t.Errorf("got %v, want FormatLogfmt", f)
	}
}

func TestParseFormat_RejectsExplicitEmpty(t *testing.T) {
	t.Parallel()
	_, err := ParseFormat("", true, "", false)
	if err == nil {
		t.Fatal("expected error for explicit empty flag value")
	}
	if !strings.Contains(err.Error(), `""`) {
		t.Errorf("error should mention the rejected value, got: %v", err)
	}
}

func TestParseFormat_RejectsUnknownFlag(t *testing.T) {
	t.Parallel()
	_, err := ParseFormat("xml", true, "", false)
	if err == nil {
		t.Fatal("expected error for unknown flag value")
	}
	if !strings.Contains(err.Error(), "xml") {
		t.Errorf("error should mention the rejected value 'xml', got: %v", err)
	}
}

func TestParseFormat_RejectsUnknownEnv(t *testing.T) {
	t.Parallel()
	_, err := ParseFormat("", false, "yaml", true)
	if err == nil {
		t.Fatal("expected error for unknown env value")
	}
	if !strings.Contains(err.Error(), "yaml") {
		t.Errorf("error should mention the rejected value 'yaml', got: %v", err)
	}
}

func TestParseFormat_RejectsCaseMismatch(t *testing.T) {
	t.Parallel()
	// "JSON" (uppercase) is not a valid value — values are case-sensitive.
	_, err := ParseFormat("JSON", true, "", false)
	if err == nil {
		t.Fatal("expected error for uppercase JSON")
	}
}

func TestParseFormat_EnvEmptyStringIgnored(t *testing.T) {
	t.Parallel()
	// envSet=true but envValue="" should fall back to default.
	f, err := ParseFormat("", false, "", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f != FormatLogfmt {
		t.Errorf("got %v, want FormatLogfmt", f)
	}
}

func TestFormatString(t *testing.T) {
	t.Parallel()
	if FormatLogfmt.String() != "logfmt" {
		t.Errorf("FormatLogfmt.String() = %q, want \"logfmt\"", FormatLogfmt.String())
	}
	if FormatJSON.String() != "json" {
		t.Errorf("FormatJSON.String() = %q, want \"json\"", FormatJSON.String())
	}
}
