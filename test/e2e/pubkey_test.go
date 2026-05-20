//go:build e2e

package e2e

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// generateE2EKeypair creates a fresh Ed25519 keypair, writes the private key
// in OpenSSH PEM format to privKeyPath (mode 0600), and writes the public key
// in authorized_keys format to authKeysPath (mode 0644).
func generateE2EKeypair(t *testing.T, privKeyPath, authKeysPath string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 keypair: %v", err)
	}
	pemBlock, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	privPEM := pem.EncodeToMemory(pemBlock)
	if err := os.WriteFile(privKeyPath, privPEM, 0o600); err != nil {
		t.Fatalf("write private key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	pubLine := ssh.MarshalAuthorizedKey(signer.PublicKey())
	if err := os.WriteFile(authKeysPath, pubLine, 0o644); err != nil {
		t.Fatalf("write authorized_keys: %v", err)
	}
}

// §13.4 #17: Pubkey auth succeeds — server started with --auth publickey
// --authorized-keys /path; a client presenting the matching key connects.
func TestE2E_PubkeyAuthSucceeds(t *testing.T) {
	t.Parallel()
	requireSSHClients(t)

	tdir := t.TempDir()
	privKeyPath := filepath.Join(tdir, "id_ed25519")
	authKeysPath := filepath.Join(tdir, "authorized_keys")
	generateE2EKeypair(t, privKeyPath, authKeysPath)

	srv := spawnServer(t, spawnOptions{
		extraArgs: []string{
			"--auth", "publickey",
			"--authorized-keys", authKeysPath,
		},
	})
	defer srv.stop()

	host, port := splitAddr(t, srv.addr)
	args := []string{"/usr/bin/ssh"}
	args = append(args, sshOpts()...)
	args = append(args,
		"-o", "BatchMode=yes",
		"-o", "IdentitiesOnly=yes",
		"-o", "PreferredAuthentications=publickey",
		"-i", privKeyPath,
		"-p", port,
		srv.user+"@"+host,
		"echo PUBKEY_OK",
	)

	// BatchMode=yes means no password prompt; pass empty password.
	res := runSSHCommand(t, args, "", nil, 20*time.Second)
	if !strings.Contains(res.output, "PUBKEY_OK") {
		t.Fatalf("expected PUBKEY_OK in output; got (exit %d):\n%s", res.exitCode, res.output)
	}
	if !srv.awaitLogContains(t, "method=publickey", 3*time.Second) {
		t.Fatalf("expected method=publickey in server log; tail:\n%s", srv.readLog(t))
	}
}

// §13.4 #17b: Pubkey auth fails with wrong key — same server config but
// a different (unregistered) key is presented; the connection is rejected.
func TestE2E_PubkeyAuthWrongKeyFails(t *testing.T) {
	t.Parallel()
	requireSSHClients(t)

	tdir := t.TempDir()
	privKeyPath := filepath.Join(tdir, "id_ed25519")
	authKeysPath := filepath.Join(tdir, "authorized_keys")
	generateE2EKeypair(t, privKeyPath, authKeysPath)

	// Generate a second "wrong" key that is NOT in authorized_keys.
	wrongKeyPath := filepath.Join(tdir, "id_wrong")
	_, wrongPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate wrong key: %v", err)
	}
	wrongPEMBlock, err := ssh.MarshalPrivateKey(wrongPriv, "")
	if err != nil {
		t.Fatalf("marshal wrong private key: %v", err)
	}
	if err := os.WriteFile(wrongKeyPath, pem.EncodeToMemory(wrongPEMBlock), 0o600); err != nil {
		t.Fatalf("write wrong key: %v", err)
	}

	srv := spawnServer(t, spawnOptions{
		extraArgs: []string{
			"--auth", "publickey",
			"--authorized-keys", authKeysPath,
		},
	})
	defer srv.stop()

	host, port := splitAddr(t, srv.addr)
	args := []string{"/usr/bin/ssh"}
	args = append(args, sshOpts()...)
	args = append(args,
		"-o", "BatchMode=yes",
		"-o", "IdentitiesOnly=yes",
		"-o", "PreferredAuthentications=publickey",
		"-i", wrongKeyPath,
		"-p", port,
		srv.user+"@"+host,
		"true",
	)

	res := runSSHCommand(t, args, "", nil, 20*time.Second)
	if res.exitCode == 0 {
		t.Fatalf("expected ssh with wrong key to fail; output:\n%s", res.output)
	}
	if !srv.awaitLogContains(t, "reason=bad-key", 3*time.Second) {
		t.Fatalf("expected reason=bad-key in server log; tail:\n%s", srv.readLog(t))
	}
}

// §13.4 #17c: Pubkey auth with both methods — server accepts password AND
// publickey; a client using the correct key succeeds via method=publickey.
func TestE2E_PubkeyAuthBothMethodsPubkeyPath(t *testing.T) {
	t.Parallel()
	requireSSHClients(t)

	tdir := t.TempDir()
	privKeyPath := filepath.Join(tdir, "id_ed25519")
	authKeysPath := filepath.Join(tdir, "authorized_keys")
	generateE2EKeypair(t, privKeyPath, authKeysPath)

	srv := spawnServer(t, spawnOptions{
		extraArgs: []string{
			"--auth", "password,publickey",
			"--authorized-keys", authKeysPath,
		},
	})
	defer srv.stop()

	host, port := splitAddr(t, srv.addr)
	args := []string{"/usr/bin/ssh"}
	args = append(args, sshOpts()...)
	args = append(args,
		"-o", "BatchMode=yes",
		"-o", "IdentitiesOnly=yes",
		"-o", "PreferredAuthentications=publickey",
		"-i", privKeyPath,
		"-p", port,
		srv.user+"@"+host,
		"echo BOTH_PUBKEY",
	)

	res := runSSHCommand(t, args, "", nil, 20*time.Second)
	if !strings.Contains(res.output, "BOTH_PUBKEY") {
		t.Fatalf("expected BOTH_PUBKEY in output; got (exit %d):\n%s", res.exitCode, res.output)
	}
	if !srv.awaitLogContains(t, "method=publickey", 3*time.Second) {
		t.Fatalf("expected method=publickey in server log; tail:\n%s", srv.readLog(t))
	}
}
