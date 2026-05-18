//go:build e2e

package e2e

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// minisshBin is the absolute path to the test binary, set by TestMain
// after `go build -cover -o $TMPDIR/minissh-test ./cmd/minissh` succeeds.
// All §13.4 cases reference this via `spawnServer`.
var minisshBin string

// coverDir is the per-process GOCOVERDIR for the spawned binary. Each
// test gets a sub-directory so the merged covdata directory keeps the
// individual runs separable for debugging.
var coverDir string

// TestMain implements the §13.4 harness rule #1: compile the binary once
// per `go test` run with `-cover` so spawned-process coverage is
// captured.
func TestMain(m *testing.M) {
	flag.Parse()

	tmpdir, err := os.MkdirTemp("", "minissh-e2e-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "mkdir tempdir: %v\n", err)
		os.Exit(2)
	}

	bin := filepath.Join(tmpdir, "minissh-test")
	coverDir = filepath.Join(tmpdir, "covdata")
	if err := os.MkdirAll(coverDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "mkdir covdata: %v\n", err)
		os.Exit(2)
	}

	repoRoot, err := findRepoRoot()
	if err != nil {
		fmt.Fprintf(os.Stderr, "find repo root: %v\n", err)
		os.Exit(2)
	}
	cmd := exec.Command("go", "build", "-cover",
		"-coverpkg=github.com/mitchellnemitz/minissh/cmd/...,github.com/mitchellnemitz/minissh/internal/...",
		"-o", bin,
		"./cmd/minissh")
	cmd.Dir = repoRoot
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "go build -cover failed: %v\n", err)
		os.Exit(2)
	}

	minisshBin = bin
	_ = os.Setenv("MINISSH_BIN", bin)

	code := m.Run()

	// Best-effort cleanup; we intentionally leave coverDir alone if a
	// caller-supplied GOCOVERDIR was set (the Makefile path), so the
	// outer coverage merge picks up the data.
	if os.Getenv("GOCOVERDIR") == "" {
		_ = os.RemoveAll(tmpdir)
	}
	os.Exit(code)
}

// findRepoRoot climbs from CWD up looking for go.mod.
func findRepoRoot() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for d := wd; d != "/" && d != ""; d = filepath.Dir(d) {
		if _, err := os.Stat(filepath.Join(d, "go.mod")); err == nil {
			return d, nil
		}
	}
	return "", errors.New("go.mod not found in any parent of " + wd)
}

// sshClientsAvailable returns true iff /usr/bin/ssh, /usr/bin/sftp, and
// /usr/bin/scp all exist. The Makefile already gates the e2e target on
// this; individual tests use the helper as a defensive double-check.
func sshClientsAvailable() bool {
	for _, p := range []string{"/usr/bin/ssh", "/usr/bin/sftp", "/usr/bin/scp"} {
		if _, err := os.Stat(p); err != nil {
			return false
		}
	}
	return true
}

// requireSSHClients skips the test when the system clients are missing.
func requireSSHClients(t *testing.T) {
	t.Helper()
	if !sshClientsAvailable() {
		t.Skip("/usr/bin/{ssh,sftp,scp} not all present")
	}
}

// requireBin is a helper for tests that assume minisshBin is set; if
// TestMain build failed it would have called os.Exit(2) already, but
// belt-and-braces.
func requireBin(t *testing.T) string {
	t.Helper()
	if minisshBin == "" {
		t.Skip("test binary not built")
	}
	return minisshBin
}

// joinArgs returns args quoted for human-readable error messages.
func joinArgs(args []string) string {
	return strings.Join(args, " ")
}
