package logging_test

import "testing"

// Integration tests assert end-to-end logging invariants by driving the
// in-process server and inspecting the captured stdout stream. Scenarios from
// spec §13.3; real bodies arrive in phase 4.

func TestIntegration_PasswordNeverAppearsInStructuredEvents(t *testing.T) {
	t.Skip("not yet implemented — phase 4")
}

func TestIntegration_AuthFailCarriesCorrectReason(t *testing.T) {
	t.Skip("not yet implemented — phase 4")
}
