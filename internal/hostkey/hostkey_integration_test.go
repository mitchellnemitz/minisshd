package hostkey_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/mitchellnemitz/minissh/internal/hostkey"
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
