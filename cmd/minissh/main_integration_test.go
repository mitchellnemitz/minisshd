package main

// Integration tests for the cmd/minissh run() function. Owned by
// test-impl (per the *_integration_test.go suffix). These tests cover
// run() paths that the package-local unit tests don't reach.

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestIntegration_RunEADDRINUSE drives the listen-time EADDRINUSE branch
// of run(): we pre-bind the target port, then invoke run() to fail with
// exitBindFailure (3) and the dedicated "already in use" stderr message.
func TestIntegration_RunEADDRINUSE(t *testing.T) {
	// Grab a port by binding to :0, then close+rebind it so run() sees
	// the EADDRINUSE error path. Race window exists but is reliably wide
	// enough on Linux loopback.
	holder, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("hold port: %v", err)
	}
	defer holder.Close()
	port := holder.Addr().(*net.TCPAddr).Port

	tmp := t.TempDir()
	hostKey := filepath.Join(tmp, "host_key")

	var stdout, stderr bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	code := run(ctx, []string{
		"--port", fmt.Sprintf("%d", port),
		"--bind", "127.0.0.1",
		"--pass", "x",
		"--user", "u",
		"--shell", "/bin/sh",
		"--host-key", hostKey,
	}, &stdout, &stderr)
	if code != 3 {
		t.Fatalf("expected exit 3 (bind failure), got %d; stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "already in use") {
		t.Errorf("expected 'already in use' in stderr; got: %q", stderr.String())
	}
}

// TestIntegration_RunEADDRNOTAVAIL drives the bind-time EADDRNOTAVAIL
// path: bind to a routable but unassigned IP literal. The exit code is
// 3 (bindFailure) and the message names the specific bind error.
func TestIntegration_RunEADDRNOTAVAIL(t *testing.T) {
	tmp := t.TempDir()
	hostKey := filepath.Join(tmp, "host_key")

	var stdout, stderr bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// 192.0.2.0/24 is TEST-NET-1 (RFC 5737), guaranteed unassigned. Even
	// if a malicious local config aliased one of these, the test still
	// hits a *bind* failure path which is what we want for coverage.
	code := run(ctx, []string{
		"--port", "0",
		"--bind", "192.0.2.42",
		"--pass", "x",
		"--user", "u",
		"--shell", "/bin/sh",
		"--host-key", hostKey,
	}, &stdout, &stderr)
	if code != 3 {
		t.Fatalf("expected exit 3 (bind failure), got %d; stderr=%q", code, stderr.String())
	}
	// Either dedicated NOT-AVAIL message or generic bind error.
	out := stderr.String()
	if !strings.Contains(out, "not assigned") && !strings.Contains(out, "bind") {
		t.Errorf("expected bind-error message; got: %q", out)
	}
}

// TestIntegration_RunHostKeyParentMissingExits4 covers the
// hostkey.ErrParentMissing → exitFSFailure case in run()'s host-key
// error switch (which the existing unit suite covers Corrupt and
// TooOpen but not ParentMissing).
func TestIntegration_RunHostKeyParentMissingExits4(t *testing.T) {
	dir := t.TempDir()
	// Caller-supplied --host-key under a non-existent parent.
	hostKey := filepath.Join(dir, "does-not-exist-subdir", "host_key")

	var stdout, stderr bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	code := run(ctx, []string{
		"--port", "0",
		"--bind", "127.0.0.1",
		"--pass", "x",
		"--user", "u",
		"--shell", "/bin/sh",
		"--host-key", hostKey,
	}, &stdout, &stderr)
	if code != 4 {
		t.Fatalf("expected exit 4 (FS failure), got %d; stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "parent") {
		t.Errorf("expected 'parent' in stderr; got: %q", stderr.String())
	}
}

// TestIntegration_EnsureMinisshDirIsFile drives the `info.IsDir() ==
// false` branch of ensureMinisshDir: the path exists but is a regular
// file, not a directory. Expected: a non-nil error mentioning "not a
// directory".
func TestIntegration_EnsureMinisshDirIsFile(t *testing.T) {
	dir := t.TempDir()
	notDir := filepath.Join(dir, "minissh-as-file")
	if err := os.WriteFile(notDir, []byte("file content\n"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	err := ensureMinisshDir(notDir)
	if err == nil {
		t.Fatalf("expected error for non-directory path; got nil")
	}
	if !strings.Contains(err.Error(), "not a directory") {
		t.Errorf("expected 'not a directory' in err; got: %v", err)
	}
}

// TestIntegration_RunHomeDirMissing drives the os.UserHomeDir failure
// branch of run() (the `!hostKeySet` arm). We unset HOME so UserHomeDir
// returns an error on Linux.
func TestIntegration_RunHomeDirMissing(t *testing.T) {
	// Save and clear HOME.
	t.Setenv("HOME", "")

	var stdout, stderr bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	code := run(ctx, []string{
		"--port", "0",
		"--bind", "127.0.0.1",
		"--pass", "x",
		"--user", "u",
		"--shell", "/bin/sh",
		// No --host-key flag, so run() tries os.UserHomeDir.
	}, &stdout, &stderr)
	if code != 4 {
		// On some Linux setups UserHomeDir still succeeds via passwd
		// lookup. Skip if so.
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			t.Skipf("UserHomeDir still resolves to %q without HOME (passwd fallback); cannot exercise this branch", home)
		}
		t.Fatalf("expected exit 4 (FS failure), got %d; stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "home") {
		t.Errorf("expected 'home directory' in stderr; got: %q", stderr.String())
	}
}
