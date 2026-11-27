//go:build e2e

package sftp

import (
	"context"
	"fmt"
	"io"
	"net"
	"path"

	pkgsftp "github.com/pkg/sftp"

	"github.com/bifrost0x/webssh/internal/ssh/client"
)

// FixtureFile is one file of a fixture file system.
type FixtureFile struct {
	Path string // absolute
	Data string
}

// Fixture is the remote file system of the restore fixture sessions of
// the e2e build (internal/terminal ReplaceFixtureSessions), as
// tests/e2e/workspace_restore.py fakes the probe, the home directory and
// the listing for the Python release. Every SFTP subsystem it opens is
// served in memory by the request server of github.com/pkg/sftp, over one
// file system per fixture, so the file source of a fixture session runs
// the real backend. Only the e2e build contains it.
type Fixture struct {
	home     string
	handlers pkgsftp.Handlers
	done     <-chan struct{}
}

// NewFixture creates the file system with the home directory and files;
// done ends every channel it serves.
func NewFixture(done <-chan struct{}, home string, files ...FixtureFile) (*Fixture, error) {
	f := &Fixture{home: home, handlers: pkgsftp.InMemHandler(), done: done}
	if err := f.seed(files); err != nil {
		return nil, err
	}
	return f, nil
}

func (f *Fixture) seed(files []FixtureFile) error {
	rwc := f.serve()
	c, err := pkgsftp.NewClientPipe(rwc, rwc)
	if err != nil {
		return fmt.Errorf("sftp fixture: %w", err)
	}
	defer c.Close()
	if err := c.MkdirAll(f.home); err != nil {
		return fmt.Errorf("sftp fixture: %w", err)
	}
	for _, file := range files {
		if err := c.MkdirAll(path.Dir(file.Path)); err != nil {
			return fmt.Errorf("sftp fixture: %w", err)
		}
		w, err := c.Create(file.Path)
		if err != nil {
			return fmt.Errorf("sftp fixture: %w", err)
		}
		_, err = io.WriteString(w, file.Data)
		if cerr := w.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return fmt.Errorf("sftp fixture: %w", err)
		}
	}
	return nil
}

// serve starts a request server on one end of a pipe and returns the
// other end; the server ends when the pipe closes or the fixture's done
// channel closes.
func (f *Fixture) serve() io.ReadWriteCloser {
	local, remote := net.Pipe()
	srv := pkgsftp.NewRequestServer(remote, f.handlers, pkgsftp.WithStartDirectory(f.home))
	ended := make(chan struct{})
	go func() {
		defer close(ended)
		_ = srv.Serve()
		_ = remote.Close()
	}()
	go func() {
		select {
		case <-f.done:
			_ = local.Close()
		case <-ended:
		}
	}()
	return local
}

// Subsystem opens the SFTP subsystem; any other subsystem is refused like
// a server without it.
func (f *Fixture) Subsystem(ctx context.Context, name string) (io.ReadWriteCloser, error) {
	if name != client.SubsystemSFTP {
		return nil, fmt.Errorf("sftp fixture: subsystem %q is not served", name)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case <-f.done:
		return nil, io.ErrClosedPipe
	default:
	}
	return f.serve(), nil
}

// Done is closed when the fixture session ends.
func (f *Fixture) Done() <-chan struct{} { return f.done }

var _ Channel = (*Fixture)(nil)
