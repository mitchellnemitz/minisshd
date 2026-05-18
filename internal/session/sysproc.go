package session

import "syscall"

// newPipeSysProcAttr returns SysProcAttr suitable for a non-PTY child: a new
// session, which implies a new process group. Spec §8 Signal handling
// requires every spawned child to be in its own process group so SIGHUP
// reaches descendants.
func newPipeSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		Setsid: true,
	}
}

// newPtySysProcAttr returns SysProcAttr for a PTY child: Setsid plus
// Setctty so the slave PTY becomes the child's controlling terminal.
func newPtySysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		Setsid:  true,
		Setctty: true,
	}
}

// applyPtySysProcAttr mutates an existing SysProcAttr to include the PTY
// flags. Used when callers pre-populate SysProcAttr for other reasons.
func applyPtySysProcAttr(s *syscall.SysProcAttr) {
	s.Setsid = true
	s.Setctty = true
}
