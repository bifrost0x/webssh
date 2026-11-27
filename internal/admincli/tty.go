package admincli

import (
	"os"

	"golang.org/x/term"
)

// OpenTerminal opens the controlling terminal, as Python's getpass tries
// /dev/tty first. It fails when the process has none, for example under
// "docker compose exec -T".
func OpenTerminal() (Terminal, error) {
	f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	if !term.IsTerminal(int(f.Fd())) { // #nosec G115 -- a file descriptor fits into int
		_ = f.Close()
		return nil, os.ErrInvalid
	}
	return &tty{f: f}, nil
}

type tty struct{ f *os.File }

func (t *tty) Write(p []byte) (int, error) { return t.f.Write(p) }

func (t *tty) ReadPassword() ([]byte, error) {
	return term.ReadPassword(int(t.f.Fd())) // #nosec G115 -- a file descriptor fits into int
}

func (t *tty) Close() error { return t.f.Close() }
