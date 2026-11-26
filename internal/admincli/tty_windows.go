//go:build windows

package admincli

import (
	"os"

	"golang.org/x/term"
)

// OpenTerminal uses the console of standard input when there is one, as
// Python's win_getpass does.
func OpenTerminal() (Terminal, error) {
	fd := int(os.Stdin.Fd()) // #nosec G115 -- a handle fits into int on Windows
	if !term.IsTerminal(fd) {
		return nil, os.ErrInvalid
	}
	return console{fd: fd}, nil
}

type console struct{ fd int }

func (c console) Write(p []byte) (int, error) { return os.Stderr.Write(p) }

func (c console) ReadPassword() ([]byte, error) { return term.ReadPassword(c.fd) }

func (console) Close() error { return nil }
