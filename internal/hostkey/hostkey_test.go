package hostkey

import (
	"bytes"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
)

// keyPath returns a fresh path inside t.TempDir() suitable for a host key.
func keyPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "host_key")
}

func TestLoadOrGenerate_MissingKeyGenerated(t *testing.T) {
	path := keyPath(t)

	signer, fp, err := LoadOrGenerate(path)
	if err != nil {
		t.Fatalf("LoadOrGenerate: %v", err)
	}
	if signer == nil {
		t.Fatal("signer is nil")
	}
	if fp == "" {
		t.Fatal("fingerprint empty")
	}
	if got, want := fp, ssh.FingerprintSHA256(signer.PublicKey()); got != want {
		t.Fatalf("fingerprint mismatch: got %q want %q", got, want)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat private key: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("private key mode = %#o, want 0600", got)
	}

	pubInfo, err := os.Stat(path + ".pub")
	if err != nil {
		t.Fatalf("stat .pub: %v", err)
	}
	if got := pubInfo.Mode().Perm(); got != 0o644 {
		t.Errorf(".pub mode = %#o, want 0644", got)
	}

	pubBytes, err := os.ReadFile(path + ".pub")
	if err != nil {
		t.Fatalf("read .pub: %v", err)
	}
	want := ssh.MarshalAuthorizedKey(signer.PublicKey())
	if !bytes.Equal(pubBytes, want) {
		t.Errorf(".pub content mismatch:\ngot  %q\nwant %q", pubBytes, want)
	}
}

func TestLoadOrGenerate_ExistingKeyLoadedUnchanged(t *testing.T) {
	path := keyPath(t)
	// Generate once.
	if _, _, err := LoadOrGenerate(path); err != nil {
		t.Fatalf("initial generate: %v", err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read after generate: %v", err)
	}

	// Load again — file bytes must not change.
	if _, _, err := LoadOrGenerate(path); err != nil {
		t.Fatalf("reload: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read after reload: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Errorf("private key bytes changed across reload")
	}
}

func TestLoadOrGenerate_TooOpenMode(t *testing.T) {
	path := keyPath(t)
	if _, _, err := LoadOrGenerate(path); err != nil {
		t.Fatalf("initial generate: %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	_, _, err := LoadOrGenerate(path)
	if !errors.Is(err, ErrKeyPermissionsTooOpen) {
		t.Fatalf("got err=%v, want ErrKeyPermissionsTooOpen", err)
	}
}

func TestLoadOrGenerate_CorruptKey(t *testing.T) {
	path := keyPath(t)
	junk := make([]byte, 5)
	if _, err := rand.Read(junk); err != nil {
		t.Fatalf("rand: %v", err)
	}
	if err := os.WriteFile(path, junk, 0o600); err != nil {
		t.Fatalf("write junk: %v", err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read junk: %v", err)
	}

	_, _, err = LoadOrGenerate(path)
	if !errors.Is(err, ErrKeyCorrupt) {
		t.Fatalf("got err=%v, want ErrKeyCorrupt", err)
	}

	// Critical: corrupt file must NOT be silently regenerated.
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read after: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Errorf("corrupt key was modified — must not silently regenerate")
	}
}

func TestLoadOrGenerate_MissingParent(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "does-not-exist")
	path := filepath.Join(parent, "host_key")

	_, _, err := LoadOrGenerate(path)
	if !errors.Is(err, ErrParentMissing) {
		t.Fatalf("got err=%v, want ErrParentMissing", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("private key file unexpectedly created at %q: %v", path, err)
	}
}

func TestLoadOrGenerate_RoundTrip(t *testing.T) {
	path := keyPath(t)

	signer1, fp1, err := LoadOrGenerate(path)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	bytes1, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read 1: %v", err)
	}

	signer2, fp2, err := LoadOrGenerate(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	bytes2, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read 2: %v", err)
	}

	if !bytes.Equal(bytes1, bytes2) {
		t.Errorf("private key bytes differ across load")
	}
	if fp1 != fp2 {
		t.Errorf("fingerprint differs: %q vs %q", fp1, fp2)
	}
	pub1 := ssh.MarshalAuthorizedKey(signer1.PublicKey())
	pub2 := ssh.MarshalAuthorizedKey(signer2.PublicKey())
	if !bytes.Equal(pub1, pub2) {
		t.Errorf("public key bytes differ across load:\n1: %q\n2: %q", pub1, pub2)
	}
}

func TestLoadOrGenerate_MissingPubRegenerated(t *testing.T) {
	path := keyPath(t)
	signer, _, err := LoadOrGenerate(path)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	want := ssh.MarshalAuthorizedKey(signer.PublicKey())

	pubPath := path + ".pub"
	if err := os.Remove(pubPath); err != nil {
		t.Fatalf("remove pub: %v", err)
	}

	if _, _, err := LoadOrGenerate(path); err != nil {
		t.Fatalf("reload: %v", err)
	}

	info, err := os.Stat(pubPath)
	if err != nil {
		t.Fatalf("stat regenerated .pub: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o644 {
		t.Errorf("regenerated .pub mode = %#o, want 0644", got)
	}
	got, err := os.ReadFile(pubPath)
	if err != nil {
		t.Fatalf("read regenerated .pub: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("regenerated .pub mismatch:\ngot  %q\nwant %q", got, want)
	}
}

func TestLoadOrGenerate_StalePubOverwritten(t *testing.T) {
	path := keyPath(t)
	signer, _, err := LoadOrGenerate(path)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	want := ssh.MarshalAuthorizedKey(signer.PublicKey())

	// Overwrite .pub with stale junk to simulate a stale or hand-edited file.
	if err := os.WriteFile(path+".pub", []byte("stale junk\n"), 0o644); err != nil {
		t.Fatalf("write stale pub: %v", err)
	}

	if _, _, err := LoadOrGenerate(path); err != nil {
		t.Fatalf("reload: %v", err)
	}
	got, err := os.ReadFile(path + ".pub")
	if err != nil {
		t.Fatalf("read .pub: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("stale .pub was not overwritten:\ngot  %q\nwant %q", got, want)
	}
}
