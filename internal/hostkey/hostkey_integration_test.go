package hostkey_test

import "testing"

// Integration tests for the host key load/generate path drive the in-process
// server across restarts using the same HOME. Scenarios from spec §13.3; real
// bodies arrive in phase 4.

func TestIntegration_HostKeyPersistsAcrossServerRestarts(t *testing.T) {
	t.Skip("not yet implemented — phase 4")
}
