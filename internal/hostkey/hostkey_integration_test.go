package hostkey_test

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/mitchellnemitz/minisshd/internal/hostkey"
)

// Integration test for host-key persistence: a regenerated key after
// deletion produces a different fingerprint, and re-loading the same
// file produces the same fingerprint.
func TestIntegration_HostKeyPersistsAcrossServerRestarts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "host_key")

	// Generate once.
	_, fp1, err := hostkey.LoadOrGenerate(path)
	if err != nil {
		t.Fatalf("LoadOrGenerate (first): %v", err)
	}
	if fp1 == "" {
		t.Fatalf("expected non-empty fingerprint")
	}

	// Re-load — should be identical.
	_, fp2, err := hostkey.LoadOrGenerate(path)
	if err != nil {
		t.Fatalf("LoadOrGenerate (second): %v", err)
	}
	if fp1 != fp2 {
		t.Fatalf("expected same fingerprint across reloads:\n  fp1=%s\n  fp2=%s", fp1, fp2)
	}

	// Delete the file and regenerate; fingerprint must differ.
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove host_key: %v", err)
	}
	// The .pub sibling may linger — that's fine for the test.
	_, fp3, err := hostkey.LoadOrGenerate(path)
	if err != nil {
		t.Fatalf("LoadOrGenerate (after delete): %v", err)
	}
	if fp3 == fp1 {
		t.Fatalf("expected different fingerprint after regeneration; got identical %s", fp3)
	}
}

// TestIntegration_HostKeyParentUnwritable drives the generateAndWrite
// error branch: parent directory exists but is read-only (mode 0o500),
// so os.WriteFile fails inside generateAndWrite. The expected outcome is
// a non-nil error and no `host_key` or `host_key.pub` file on disk.
func TestIntegration_HostKeyParentUnwritable(t *testing.T) {
	// Skip on darwin/windows etc. that may surface different permission
	// semantics; the spec is macOS-first and POSIX umask is honored
	// identically on Linux for the read-only parent case.
	if runtime.GOOS == "windows" {
		t.Skip("permissions-based test not portable to windows")
	}
	// Running as root bypasses DAC mode checks; the WriteFile would
	// succeed and the test would falsely pass.
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses 0o500 parent mode check")
	}

	parent := t.TempDir()
	if err := os.Chmod(parent, 0o500); err != nil {
		t.Fatalf("chmod parent: %v", err)
	}
	// Restore writable mode at the end so t.TempDir cleanup can run.
	t.Cleanup(func() { _ = os.Chmod(parent, 0o700) })

	path := filepath.Join(parent, "host_key")
	_, _, err := hostkey.LoadOrGenerate(path)
	if err == nil {
		t.Fatalf("expected error when parent is read-only; got nil")
	}
	// We don't pin the sentinel here — generateAndWrite wraps a raw
	// fs error, which is not a defined sentinel — but the error path
	// MUST surface and MUST NOT leave either file on disk.
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Errorf("expected no host_key on read-only parent; stat err=%v", statErr)
	}
	if _, statErr := os.Stat(path + ".pub"); !os.IsNotExist(statErr) {
		t.Errorf("expected no host_key.pub on read-only parent; stat err=%v", statErr)
	}
}

// TestIntegration_HostKeyPubModeFixedOnRegen pre-creates a stale .pub
// sibling at mode 0o600 and a corresponding private key at 0o600, then
// runs LoadOrGenerate. The contract from §6 says: every successful load
// re-derives the .pub at 0o644. This drives the writePub mode-fix branch
// from a pre-existing-file starting state.
func TestIntegration_HostKeyPubModeFixedOnRegen(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permissions-based test not portable to windows")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "host_key")

	// Generate a valid private key.
	if _, _, err := hostkey.LoadOrGenerate(path); err != nil {
		t.Fatalf("initial generate: %v", err)
	}
	// Now corrupt the .pub mode (private stays 0600).
	pubPath := path + ".pub"
	if err := os.Chmod(pubPath, 0o600); err != nil {
		t.Fatalf("chmod pub to 0o600: %v", err)
	}
	// Sanity-check the pre-state.
	if info, err := os.Stat(pubPath); err != nil {
		t.Fatalf("stat .pub: %v", err)
	} else if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("pre-state: .pub mode = %#o, want 0o600", got)
	}

	if _, _, err := hostkey.LoadOrGenerate(path); err != nil {
		t.Fatalf("reload: %v", err)
	}
	// Post-state: private 0o600, public 0o644.
	pinfo, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat private: %v", err)
	}
	if got := pinfo.Mode().Perm(); got != 0o600 {
		t.Errorf("private key mode = %#o, want 0o600", got)
	}
	pubInfo, err := os.Stat(pubPath)
	if err != nil {
		t.Fatalf("stat .pub: %v", err)
	}
	if got := pubInfo.Mode().Perm(); got != 0o644 {
		t.Errorf(".pub mode = %#o, want 0o644 after reload", got)
	}
}

// TestIntegration_HostKeyMissingParentSentinel pins the spec §6
// ErrParentMissing sentinel via the public LoadOrGenerate surface (the
// package-local unit test does the same but reaching the sentinel from a
// downstream package is part of the public-API contract).
func TestIntegration_HostKeyMissingParentSentinel(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "missing-subdir")
	path := filepath.Join(parent, "host_key")
	_, _, err := hostkey.LoadOrGenerate(path)
	if !errors.Is(err, hostkey.ErrParentMissing) {
		t.Fatalf("got err=%v, want wrapping hostkey.ErrParentMissing", err)
	}
}

// TestIntegration_HostKeyParentIsFile drives the second branch of the
// ErrParentMissing surface: the parent path exists but is a regular file,
// not a directory. We want spec §6 to error rather than try to create
// children under a non-directory.
func TestIntegration_HostKeyParentIsFile(t *testing.T) {
	dir := t.TempDir()
	parent := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(parent, []byte("regular file\n"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	path := filepath.Join(parent, "host_key")
	_, _, err := hostkey.LoadOrGenerate(path)
	if !errors.Is(err, hostkey.ErrParentMissing) {
		t.Fatalf("got err=%v, want wrapping hostkey.ErrParentMissing", err)
	}
}

// TestIntegration_HostKeyPubWriteCollidesWithDirectory exercises the
// generateAndWrite → writePub error branch in `internal/hostkey/hostkey.go`.
// When the .pub path is already occupied by a directory, os.WriteFile fails
// and the wrapped error propagates back through LoadOrGenerate. This was
// a low-coverage branch (64.7% on generateAndWrite) because the spec-required
// scenarios never trip it.
func TestIntegration_HostKeyPubWriteCollidesWithDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix-only mode semantics")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "host_key")
	// Pre-create the .pub sibling as a directory to make writePub's
	// os.WriteFile call fail with EISDIR.
	pubPath := path + ".pub"
	if err := os.Mkdir(pubPath, 0o700); err != nil {
		t.Fatal(err)
	}
	_, _, err := hostkey.LoadOrGenerate(path)
	if err == nil {
		t.Fatalf("expected error when %s is a directory; got nil", pubPath)
	}
	// The private key may or may not have been written before writePub
	// failed (it is on the current implementation, which writes private
	// first); either way we just assert the error surfaces.
	if errors.Is(err, hostkey.ErrParentMissing) ||
		errors.Is(err, hostkey.ErrKeyCorrupt) ||
		errors.Is(err, hostkey.ErrKeyPermissionsTooOpen) {
		t.Errorf("error should be a write-failure surface, not a sentinel; got %v", err)
	}
}
