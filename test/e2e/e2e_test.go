//go:build e2e

package e2e

import "testing"

// E2E tests compile the binary with `go build -cover` and drive it with the
// system ssh/sftp/scp clients, answering password prompts via a PTY
// (creack/pty). Scenarios enumerated from spec §13.4; real bodies arrive in
// phase 4.

func TestE2E_Placeholder(t *testing.T) {
	t.Skip("E2E suite scaffolded; real tests arrive in phase 4")
}
