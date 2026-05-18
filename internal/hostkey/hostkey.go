// Package hostkey loads and generates the persistent Ed25519 host key
// described in spec §6.
package hostkey

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
)

// Sentinel errors. cmd/minissh maps these to exit codes via errors.Is.
var (
	// ErrParentMissing is returned when the parent directory of the key
	// path does not exist. cmd/minissh maps this to exit 4. The host key
	// loader never auto-creates non-default parent directories (§6).
	ErrParentMissing = errors.New("host key parent directory missing")

	// ErrKeyPermissionsTooOpen is returned when the private key file has
	// any bits set beyond 0600. cmd/minissh maps this to exit 4 with a
	// `chmod 600` message (§6).
	ErrKeyPermissionsTooOpen = errors.New("host key permissions too open")

	// ErrKeyCorrupt is returned when the private key file exists with
	// correct mode but cannot be parsed (§6: do not silently regenerate).
	ErrKeyCorrupt = errors.New("host key corrupt")
)

// LoadOrGenerate loads the Ed25519 host key at path, generating it if it does
// not exist. The semantics match spec §6:
//
//   - The parent directory must exist; if not, the returned error wraps
//     ErrParentMissing. The function never creates the parent.
//   - If the private key file is missing, an Ed25519 keypair is generated,
//     the private key is written in OpenSSH PEM format at mode 0600, and the
//     public key is written at path+".pub" in authorized_keys format at 0644.
//   - If the private key file exists with any bits beyond 0600, the returned
//     error wraps ErrKeyPermissionsTooOpen.
//   - If the private key file exists but cannot be parsed, the returned error
//     wraps ErrKeyCorrupt. The file is not regenerated.
//   - On every successful load, path+".pub" is re-derived from the private key
//     and overwritten at mode 0644, handling stale or missing .pub files.
//
// fingerprint is the ssh.FingerprintSHA256 of the public key.
func LoadOrGenerate(path string) (ssh.Signer, string, error) {
	parent := filepath.Dir(path)
	if info, err := os.Stat(parent); err != nil {
		if os.IsNotExist(err) {
			return nil, "", fmt.Errorf("host key parent directory %q: %w", parent, ErrParentMissing)
		}
		return nil, "", fmt.Errorf("stat host key parent %q: %w", parent, err)
	} else if !info.IsDir() {
		return nil, "", fmt.Errorf("host key parent %q is not a directory: %w", parent, ErrParentMissing)
	}

	info, err := os.Stat(path)
	switch {
	case err == nil:
		// Existing key — validate mode, then load.
		mode := info.Mode().Perm()
		if mode&^0o600 != 0 {
			return nil, "", fmt.Errorf("host key %q has mode %#o (run `chmod 600 %s`): %w",
				path, mode, path, ErrKeyPermissionsTooOpen)
		}
		return loadExisting(path)
	case os.IsNotExist(err):
		return generateAndWrite(path)
	default:
		return nil, "", fmt.Errorf("stat host key %q: %w", path, err)
	}
}

// generateAndWrite creates a fresh Ed25519 keypair, writes the private key in
// OpenSSH PEM format at mode 0600 and the .pub sibling at mode 0644.
func generateAndWrite(path string) (ssh.Signer, string, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", fmt.Errorf("generate ed25519 key: %w", err)
	}

	pemBlock, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		return nil, "", fmt.Errorf("marshal private key: %w", err)
	}
	data := pem.EncodeToMemory(pemBlock)

	// Create with 0600 explicitly, then chmod defensively in case umask or
	// an existing file (race) left wider bits.
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return nil, "", fmt.Errorf("write host key %q: %w", path, err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return nil, "", fmt.Errorf("chmod host key %q: %w", path, err)
	}

	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, "", fmt.Errorf("derive signer: %w", err)
	}

	if err := writePub(path, signer); err != nil {
		return nil, "", err
	}

	return signer, ssh.FingerprintSHA256(signer.PublicKey()), nil
}

// loadExisting parses the private key file at path. It then re-derives the
// public key and overwrites path+".pub" at mode 0644 (§6 `.pub` regeneration).
func loadExisting(path string) (ssh.Signer, string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", fmt.Errorf("read host key %q: %w", path, err)
	}
	signer, err := ssh.ParsePrivateKey(data)
	if err != nil {
		return nil, "", fmt.Errorf("parse host key %q: %w: %w", path, err, ErrKeyCorrupt)
	}
	if err := writePub(path, signer); err != nil {
		return nil, "", err
	}
	return signer, ssh.FingerprintSHA256(signer.PublicKey()), nil
}

// writePub writes the authorized_keys-format public key to path+".pub" at
// mode 0644, overwriting any prior contents.
func writePub(path string, signer ssh.Signer) error {
	pubPath := path + ".pub"
	pubBytes := ssh.MarshalAuthorizedKey(signer.PublicKey())
	if err := os.WriteFile(pubPath, pubBytes, 0o644); err != nil {
		return fmt.Errorf("write public key %q: %w", pubPath, err)
	}
	// Defensive chmod in case an existing file had wider bits.
	if err := os.Chmod(pubPath, 0o644); err != nil {
		return fmt.Errorf("chmod public key %q: %w", pubPath, err)
	}
	return nil
}
