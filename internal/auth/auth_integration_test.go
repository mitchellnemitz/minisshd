package auth_test

import "testing"

// Integration tests for the auth path drive the in-process server via
// golang.org/x/crypto/ssh as the client. Scenarios are enumerated from
// spec §13.3; real bodies arrive in phase 4.

func TestIntegration_CorrectCredentialsAllowShell(t *testing.T) {
	t.Skip("not yet implemented — phase 4")
}

func TestIntegration_WrongUserLogsBadUser(t *testing.T) {
	t.Skip("not yet implemented — phase 4")
}

func TestIntegration_WrongPasswordLogsBadPassword(t *testing.T) {
	t.Skip("not yet implemented — phase 4")
}

func TestIntegration_ThreeWrongPasswordsCloseConnectionAfterThirdAttempt(t *testing.T) {
	t.Skip("not yet implemented — phase 4")
}
