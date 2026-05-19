package auth_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/mitchellnemitz/minisshd/internal/auth"
)

// TestIntegration_LoadParsesOpenSSHFormat loads a fixture file written by
// ssh.MarshalAuthorizedKey (the format produced by ssh-keygen) and asserts
// the count and fingerprints are correct.
func TestIntegration_LoadParsesOpenSSHFormat(t *testing.T) {
	// Generate two keys and write them in OpenSSH authorized_keys format.
	keys := make([]ssh.PublicKey, 2)
	for i := range keys {
		signer := generateIntegrationKey(t)
		keys[i] = signer.PublicKey()
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "authorized_keys")
	var content []byte
	for _, k := range keys {
		content = append(content, ssh.MarshalAuthorizedKey(k)...)
	}
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	ks := auth.NewKeysetSource(path, noopLogger{})
	if err := ks.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := ks.Count(); got != 2 {
		t.Errorf("Count = %d, want 2", got)
	}

	// Each key must be accepted.
	for i, pub := range keys {
		ok, reason, fp := ks.Current().Check(pub)
		if !ok {
			t.Errorf("key[%d] not accepted; reason=%q", i, reason)
		}
		wantFP := ssh.FingerprintSHA256(pub)
		if fp != wantFP {
			t.Errorf("key[%d] fingerprint = %q, want %q", i, fp, wantFP)
		}
	}
}

// TestIntegration_ReloadObservesFileChange writes a first key, loads it,
// overwrites the file with a second key, reloads, and asserts that only the
// second key is now accepted.
func TestIntegration_ReloadObservesFileChange(t *testing.T) {
	pub1 := generateIntegrationKey(t).PublicKey()
	pub2 := generateIntegrationKey(t).PublicKey()

	dir := t.TempDir()
	path := filepath.Join(dir, "authorized_keys")

	// Write and load key 1.
	if err := os.WriteFile(path, ssh.MarshalAuthorizedKey(pub1), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	rl := &recordingIntegrationLogger{}
	ks := auth.NewKeysetSource(path, rl)
	if err := ks.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if ks.Count() != 1 {
		t.Fatalf("Count after load = %d, want 1", ks.Count())
	}

	// Overwrite with key 2.
	if err := os.WriteFile(path, ssh.MarshalAuthorizedKey(pub2), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := ks.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if ks.Count() != 1 {
		t.Fatalf("Count after reload = %d, want 1", ks.Count())
	}

	// Key 2 should be accepted; key 1 should not.
	ok2, _, _ := ks.Current().Check(pub2)
	if !ok2 {
		t.Error("key2 should be accepted after reload")
	}
	ok1, _, _ := ks.Current().Check(pub1)
	if ok1 {
		t.Error("key1 should be rejected after reload (replaced by key2)")
	}

	// PubkeyReloadOK should have been emitted.
	if len(rl.reloadOK) == 0 {
		t.Error("expected PubkeyReloadOK event")
	}
}

// --- helpers -----------------------------------------------------------------

// noopLogger satisfies the narrow pubkeyLogger interface expected by
// auth.NewKeysetSource. Integration tests that do not need events use this.
type noopLogger struct{}

func (noopLogger) PubkeyParseError(_ string, _ int, _ string)    {}
func (noopLogger) PubkeyOptionIgnored(_ string, _ int, _ string) {}
func (noopLogger) PubkeyKeysMissing(_ string)                    {}
func (noopLogger) PubkeyReloadOK(_ string, _ int)                {}
func (noopLogger) PubkeyReloadFailed(_ string, _ string)         {}

// recordingIntegrationLogger records events for assertions.
type recordingIntegrationLogger struct {
	reloadOK     []int
	reloadFailed []string
}

func (r *recordingIntegrationLogger) PubkeyParseError(_ string, _ int, _ string)    {}
func (r *recordingIntegrationLogger) PubkeyOptionIgnored(_ string, _ int, _ string) {}
func (r *recordingIntegrationLogger) PubkeyKeysMissing(_ string)                    {}
func (r *recordingIntegrationLogger) PubkeyReloadOK(_ string, count int) {
	r.reloadOK = append(r.reloadOK, count)
}
func (r *recordingIntegrationLogger) PubkeyReloadFailed(_ string, msg string) {
	r.reloadFailed = append(r.reloadFailed, msg)
}

// generateIntegrationKey returns a fresh ed25519 signer for tests.
func generateIntegrationKey(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("ssh.NewSignerFromKey: %v", err)
	}
	return signer
}
