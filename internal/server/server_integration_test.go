package server_test

import "testing"

// Integration tests for the SSH server drive the in-process server via
// golang.org/x/crypto/ssh as the client. Scenarios enumerated from spec §13.3;
// real bodies arrive in phase 4.

func TestIntegration_ExecChannelReturnsExitCode(t *testing.T) {
	t.Skip("not yet implemented — phase 4")
}

func TestIntegration_SFTPRoundTrip1MB(t *testing.T) {
	t.Skip("not yet implemented — phase 4")
}

func TestIntegration_TwentyConcurrentExecs(t *testing.T) {
	t.Skip("not yet implemented — phase 4")
}

func TestIntegration_RejectsDirectTCPIP(t *testing.T) {
	t.Skip("not yet implemented — phase 4")
}

func TestIntegration_RejectsX11Req(t *testing.T) {
	t.Skip("not yet implemented — phase 4")
}

func TestIntegration_InteractiveShellLoadsZshrc(t *testing.T) {
	t.Skip("not yet implemented — phase 4")
}

func TestIntegration_ExecDoesNotLoadZshrc(t *testing.T) {
	t.Skip("not yet implemented — phase 4")
}

func TestIntegration_BareShellLoadsZprofileButNotZshrc(t *testing.T) {
	t.Skip("not yet implemented — phase 4")
}

func TestIntegration_ExecWithPtyLoadsZshrcAndHasTERM(t *testing.T) {
	t.Skip("not yet implemented — phase 4")
}
