package main

import (
	"context"

	"github.com/bifrost0x/webssh/internal/config"
	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/files"
	"github.com/bifrost0x/webssh/internal/files/sftp"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
	"github.com/bifrost0x/webssh/internal/ssh/client"
	"github.com/bifrost0x/webssh/internal/terminal"
)

// sftpArea wires the area "sftp" (FS2): the SFTP file backend
// (internal/files/sftp). The terminal session's own source opens on first
// use over the session's connection; Quick SFTP dials like the terminal
// and asks about host keys with its prompts (D-22). The file source
// registry of the files area owns both sources and their quota.
func sftpArea() extension {
	return extension{name: "sftp", wire: wireSFTP}
}

func wireSFTP(sys *system) error {
	opts := sftpOptions(sys.cfg.Files)
	chmod := func(ctx context.Context) bool {
		app, err := sys.settings.App(ctx)
		return err == nil && app.RuntimeFeature("sftp_chmod_enabled").Enabled
	}
	sessions := terminalFiles{sys.terminal}
	sys.fileSources.RegisterKind(files.SourceSFTPSession, func(ctx context.Context, p principal.Principal, handle string) (files.Descriptor, files.Backend, error) {
		o := opts
		o.ChmodEnabled = chmod(ctx)
		return sftp.SessionOpener(sessions, o)(ctx, p, handle)
	})
	sys.terminal.SetFileSources(sessions.fileSource(sys.fileSources))
	area := &sftp.Area{
		Quick:    &sftp.Quick{Dialer: sys.shells, Options: opts, Chmod: chmod},
		Registry: sys.fileSources, Connector: sessions, Sessions: sessions,
	}
	sys.realtime.Mount(area.Routes()...)
	return nil
}

// sftpOptions are the protocol limits of the configuration.
func sftpOptions(f config.Files) sftp.Options {
	return sftp.Options{
		MaxPacketBytes: f.SFTP.MaxPacketBytes, MaxHandleBytes: f.SFTP.MaxHandleBytes,
		MaxNameBytes: f.SFTP.MaxNameBytes, MaxMetadataBytes: f.SFTP.MaxMetadataBytes,
		MaxMembers: f.MaxTransferMembers, OperationTimeout: f.SFTP.OperationTimeout,
	}
}

// terminalFiles adapts the terminal to the SFTP sources: a session's
// connection for its file source and directory probe, and the target
// checks and prompts of terminal.open for Quick SFTP.
type terminalFiles struct{ m *terminal.Manager }

// fixtureFiles serves the file source of the restore fixture sessions of
// the end-to-end build (e2e_restore.go); nil in every other build.
var fixtureFiles func(m *terminal.Manager, owner int64, handle string) (sftp.Session, bool)

func (t terminalFiles) Session(_ context.Context, p principal.Principal, handle string) (sftp.Session, error) {
	// An unknown, foreign or ended session is a source that is not
	// available, whichever it was.
	f, err := t.m.SessionConn(p.UserID, handle)
	if err != nil {
		if fixtureFiles != nil {
			if s, ok := fixtureFiles(t.m, p.UserID, handle); ok {
				return s, nil
			}
		}
		return sftp.Session{}, fault.New(fault.SourceUnavailable, "")
	}
	return sftp.Session{Conn: f.Conn, Exec: f.Conn, Tmux: f.Tmux, Name: f.Name, InputIdle: f.InputIdle,
		Hop: client.Hop{Host: f.Host, Port: f.Port, User: f.Username}}, nil
}

// fileSource describes a terminal session's own source for the page: the
// open source of the caller's browser session with its real capabilities,
// else the descriptor before the first use (_public_file_source).
func (terminalFiles) fileSource(reg *files.Registry) terminal.FileSources {
	return func(p principal.Principal, info protocol.SessionInfo) *protocol.FileSource {
		if id, err := files.FormatSourceID(files.SourceSFTPSession, info.SessionID); err == nil {
			if d, caps, err := reg.Describe(p, id); err == nil {
				fs := files.PublicSource(d, caps)
				return &fs
			}
		}
		fs, err := sftp.SessionSource(info.SessionID, sftp.Session{Name: info.DisplayName,
			Hop: client.Hop{Host: info.Host, Port: info.Port, User: info.Username}})
		if err != nil {
			return nil
		}
		return &fs
	}
}

func (t terminalFiles) Target(ctx context.Context, owner int64, req protocol.OpenTarget) (client.Target, error) {
	return t.m.Target(ctx, owner, req)
}

func (t terminalFiles) Interaction(peer protocol.Peer, requestID string) client.Interaction {
	return t.m.Interaction(peer, requestID)
}

func (terminalFiles) NeedsVariant(t client.Target) bool { return terminal.NeedsVariant(t) }

func (t terminalFiles) PrepareFiles(ctx context.Context, peer protocol.Peer, requestID string, target client.Target) (client.Target, context.Context, func(), error) {
	return t.m.PrepareFiles(ctx, peer, requestID, target)
}

var (
	_ sftp.Sessions  = terminalFiles{}
	_ sftp.Connector = terminalFiles{}
	_ sftp.Registry  = (*files.Registry)(nil)
	_ sftp.Dialer    = legacyAlgorithmShells{}
)
