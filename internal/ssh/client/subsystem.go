package client

import (
	"context"
	"errors"
	"io"
	"sync"

	"golang.org/x/crypto/ssh"

	"github.com/bifrost0x/webssh/internal/fault"
)

// Subsystems a caller may start. The list is closed: the name is sent to
// the server as is.
const SubsystemSFTP = "sftp"

// Subsystem starts the named subsystem on its own channel and returns the
// channel's data stream. Opening the channel and the subsystem request are
// bounded by the handshake timeout like a shell; a peer that stalls there,
// or the end of ctx meanwhile, closes the whole connection. Closing the
// stream ends the channel and leaves the connection open.
func (c *Conn) Subsystem(ctx context.Context, name string) (io.ReadWriteCloser, error) {
	if name != SubsystemSFTP {
		return nil, fault.New(fault.InvalidValue, "The subsystem is not supported.")
	}
	gctx, disarm := c.guard(ctx)
	s, err := c.client.NewSession()
	if err != nil {
		return nil, setupFail(ctx, gctx, disarm(), err)
	}
	failWith := func(err error) (io.ReadWriteCloser, error) {
		fired := disarm()
		_ = s.Close()
		return nil, setupFail(ctx, gctx, fired, err)
	}
	stdin, err := s.StdinPipe()
	if err != nil {
		return failWith(err)
	}
	stdout, err := s.StdoutPipe()
	if err != nil {
		return failWith(err)
	}
	if err := s.RequestSubsystem(name); err != nil {
		return failWith(err)
	}
	if disarm() {
		_ = s.Close()
		return nil, setupFail(ctx, gctx, true, nil)
	}
	return &subsystem{session: s, stdin: stdin, stdout: stdout}, nil
}

type subsystem struct {
	session *ssh.Session
	stdin   io.WriteCloser
	stdout  io.Reader
	once    sync.Once
	err     error
}

func (s *subsystem) Read(p []byte) (int, error)  { return s.stdout.Read(p) }
func (s *subsystem) Write(p []byte) (int, error) { return s.stdin.Write(p) }

// Close ends the channel. It is safe to call more than once.
func (s *subsystem) Close() error {
	s.once.Do(func() {
		s.err = s.session.Close()
		if errors.Is(s.err, io.EOF) {
			s.err = nil
		}
	})
	return s.err
}

// ConnOf returns the connection a shell of this package runs on, for the
// channels a terminal session opens beside its shell (the SFTP subsystem
// of its file source, the directory probe). Other shells give nil.
func ConnOf(s Shell) *Conn {
	if sh, ok := s.(*shell); ok {
		return sh.conn
	}
	return nil
}
