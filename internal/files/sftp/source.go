package sftp

import (
	"context"
	"io"
	"strconv"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/files"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/ssh/client"
)

// Channel opens the SFTP subsystem on an SSH connection
// (*client.Conn satisfies it).
type Channel interface {
	Subsystem(ctx context.Context, name string) (io.ReadWriteCloser, error)
	Done() <-chan struct{}
}

// Dialer is the shared SSH dialer (*client.Dialer): Quick SFTP connects
// like the terminal, through jump hosts or SOCKS5, with the same host-key
// prompt (D-22).
type Dialer interface {
	Dial(ctx context.Context, t client.Target, ix client.Interaction) (*client.Conn, error)
}

// openOn starts the backend on conn. closeConn closes the SSH connection
// when the backend ends (Quick SFTP); a terminal session keeps its
// connection. The backend also ends when the connection ends.
func openOn(ctx context.Context, conn Channel, o Options, onClose func()) (*Backend, error) {
	ch, err := conn.Subsystem(ctx, client.SubsystemSFTP)
	if err != nil {
		if onClose != nil {
			onClose()
		}
		return nil, err
	}
	b, err := Open(ctx, ch, o)
	if err != nil {
		if onClose != nil {
			onClose()
		}
		return nil, err
	}
	b.onClose = onClose
	go func() {
		select {
		case <-conn.Done():
		case <-b.Done():
		}
		_ = b.Close()
	}()
	return b, nil
}

func descriptor(h client.Hop, name string, ephemeral bool) files.Descriptor {
	label := name
	if label == "" {
		label = h.User + "@" + h.Host
	}
	return files.Descriptor{
		Kind: files.KindSFTP, Label: label, Endpoint: h.Host + ":" + strconv.Itoa(h.Port),
		Protocol: "SFTP", Ephemeral: ephemeral,
		Security: files.Security{HostKeyVerified: true},
	}
}

// Quick opens Quick SFTP sources: an SSH connection without a PTY for one
// file source, also for a saved host (the caller resolves it to a
// Target). The caller reserves the quota before it opens one
// (files.Registry.Reserve); the source registry owns it.
type Quick struct {
	Dialer  Dialer
	Options Options
	// Chmod, when set, reads the admin switch sftp_chmod_enabled for each
	// new source instead of Options.ChmodEnabled.
	Chmod func(context.Context) bool
}

// Open connects to t for p and starts SFTP. ix answers the host-key and
// banner prompts like in the terminal; an unknown key is asked for, a
// changed key is refused (D-22; the Python release refused unknown keys).
// The returned backend owns the connection.
func (q *Quick) Open(ctx context.Context, p principal.Principal, t client.Target, ix client.Interaction) (files.Descriptor, *Backend, error) {
	if q.Dialer == nil || p.UserID <= 0 {
		return files.Descriptor{}, nil, fault.New(fault.SourceUnavailable, "")
	}
	t.Owner = p.UserID
	conn, err := q.Dialer.Dial(ctx, t, ix)
	if err != nil {
		return files.Descriptor{}, nil, err
	}
	o := q.Options
	if q.Chmod != nil {
		o.ChmodEnabled = q.Chmod(ctx)
	}
	b, err := openOn(ctx, conn, o, func() { _ = conn.Close() })
	if err != nil {
		return files.Descriptor{}, nil, err
	}
	return descriptor(t.Hop, t.Display.Name, true), b, nil
}

// Session is a terminal session's connection as the SFTP source needs it.
type Session struct {
	Conn Channel
	Hop  client.Hop // host, port and user for the descriptor
	Name string     // display name of the session, if any
	// Exec runs the directory probe on the same connection; Tmux is the
	// tmux session the shell runs in, if any.
	Exec Execer
	Tmux string
	// InputIdle reports whether the shell shows a prompt nobody typed into
	// (prompt_input_idle); nil: never idle.
	InputIdle func() bool
}

// Sessions finds a terminal session of p by its handle
// (internal/terminal, adapted in cmd/webssh). An unknown or foreign
// handle fails with fault.SourceUnavailable.
type Sessions interface {
	Session(ctx context.Context, p principal.Principal, handle string) (Session, error)
}

// SessionOpener is the opener of the kind sftp-session (a files.Opener): SFTP on the
// connection of a terminal session. Closing the source closes its channel
// only; the terminal keeps the connection.
func SessionOpener(s Sessions, o Options) func(context.Context, principal.Principal, string) (files.Descriptor, files.Backend, error) {
	return func(ctx context.Context, p principal.Principal, handle string) (files.Descriptor, files.Backend, error) {
		sess, err := s.Session(ctx, p, handle)
		if err != nil {
			return files.Descriptor{}, nil, err
		}
		b, err := openOn(ctx, sess.Conn, o, nil)
		if err != nil {
			return files.Descriptor{}, nil, err
		}
		return descriptor(sess.Hop, sess.Name, false), b, nil
	}
}

// ProbeTimeout bounds the capability probe (CAPABILITY_TIMEOUT).
const ProbeTimeout = 3 * time.Second

// Probe tells whether a terminal session can browse files: it opens SFTP
// on a short-lived channel and reads the first entries of the login
// directory, within ProbeTimeout (probe_sftp_capability). A refused
// channel (the server's session limit) keeps its code
// fault.ChannelRejected, the Python resource_shortage answer.
func Probe(ctx context.Context, conn Channel, o Options) error {
	ctx, cancel := context.WithTimeout(ctx, ProbeTimeout)
	defer cancel()
	o.OperationTimeout = min(o.withDefaults().OperationTimeout, ProbeTimeout)
	ch, err := conn.Subsystem(ctx, client.SubsystemSFTP)
	if err != nil {
		return err
	}
	b, err := Open(ctx, ch, o)
	if err != nil {
		return err
	}
	defer b.Close()
	home, err := b.Home(ctx)
	if err != nil {
		return err
	}
	l, err := b.OpenListing(ctx, home)
	if err != nil {
		return err
	}
	defer l.Close()
	_, _, err = l.Next(ctx, 1)
	return err
}
