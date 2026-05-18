package session

import (
	"io"
	"os"
	"os/exec"

	"github.com/creack/pty"
)

// ptyHandle abstracts the master side of a PTY so tests can substitute a
// fake. Production code uses *os.File from creack/pty; tests use a mock
// that records Setsize calls.
type ptyHandle interface {
	io.ReadWriter
	io.Closer
	// Setsize updates the kernel's record of the terminal dimensions and
	// dispatches SIGWINCH to the foreground process group.
	Setsize(cols, rows, widthPx, heightPx uint32) error
	// File returns the underlying *os.File, or nil for mocks. The
	// production path needs the *os.File to attach to the child process
	// via creack/pty.
	File() *os.File
}

// ptyAllocator allocates a PTY pair. Real code uses creackOpen; tests can
// inject a failing allocator to drive the §11 PTY-allocation-failure path.
type ptyAllocator func() (master ptyHandle, slave *os.File, err error)

// creackOpen wraps creack/pty.Open and adapts the *os.File master to the
// ptyHandle interface.
func creackOpen() (ptyHandle, *os.File, error) {
	master, slave, err := pty.Open()
	if err != nil {
		return nil, nil, err
	}
	return ptyFile{master}, slave, nil
}

// ptyFile is the production ptyHandle adapter around an *os.File master.
type ptyFile struct {
	f *os.File
}

func (p ptyFile) Read(b []byte) (int, error)  { return p.f.Read(b) }
func (p ptyFile) Write(b []byte) (int, error) { return p.f.Write(b) }
func (p ptyFile) Close() error                { return p.f.Close() }
func (p ptyFile) File() *os.File              { return p.f }

func (p ptyFile) Setsize(cols, rows, widthPx, heightPx uint32) error {
	return pty.Setsize(p.f, &pty.Winsize{
		Cols: uint16(cols),
		Rows: uint16(rows),
		X:    uint16(widthPx),
		Y:    uint16(heightPx),
	})
}

// startWithPTY attaches the slave end of the given PTY pair to cmd's stdio
// and starts the process. The slave is closed in the parent on success so
// the master EOFs when the child exits.
func startWithPTY(cmd *exec.Cmd, slave *os.File) error {
	cmd.Stdin = slave
	cmd.Stdout = slave
	cmd.Stderr = slave
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = newPtySysProcAttr()
	} else {
		applyPtySysProcAttr(cmd.SysProcAttr)
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	// The child has its own copy of the slave fd now; close the parent's
	// so the master returns EOF after child exit.
	_ = slave.Close()
	return nil
}
