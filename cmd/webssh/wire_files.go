package main

import (
	"context"
	"time"

	"github.com/bifrost0x/webssh/internal/audit"
	"github.com/bifrost0x/webssh/internal/config"
	"github.com/bifrost0x/webssh/internal/files"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/quota"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
)

// filesArea wires the area "files" (FS1): the file workspace and the editor (internal/files).
// FS1 fills in the hooks; no other package edits this file.
//
// The registry and the service exist after prepare, so the backend areas
// that follow (sftp, smb) register their source kinds on sys.fileSources.
// The registry owns the quick-connection quota of Quick SFTP and SMB
// sources and learns every realtime connection of a user.
func filesArea() extension {
	return extension{
		name:       "files",
		prepare:    prepareFiles,
		wire:       wireFiles,
		background: sweepFileSources,
	}
}

func prepareFiles(sys *system) error {
	sys.fileSources = files.NewRegistry(files.RegistryOptions{Quotas: sys.quotas, RouteRestricted: sys.tailnetRestrictedNow})
	sys.files = files.New(fileOptions(sys.cfg.Files, sys.fileSources, sys.audit))
	sys.closers = append(sys.closers, func() error { sys.fileSources.Shutdown(); return nil })
	return nil
}

func fileOptions(f config.Files, reg *files.Registry, audit files.Audit) files.Options {
	return files.Options{
		Registry: reg, Audit: audit,
		PageSize: f.ListingPageSize, SnapshotTTL: f.SnapshotTTL, SnapshotsPerUser: f.SnapshotsPerUser,
		SnapshotsTotal: f.SnapshotsTotal, MaxMembers: f.MaxTransferMembers,
		MaxEditorBytes: f.MaxEditorBytes, EditorBytesPerMinute: f.EditorBytesPerMinute,
		ControlBytesPerMin: f.ControlBytesPerMin, MaxPreviewBytes: f.MaxPreviewBytes,
		MaxPreviewTailLines: f.MaxPreviewTailLines, MaxSupportedFileSize: f.MaxSupportedFileSize,
		MaxPathBytes: f.MaxPathBytes,
	}
}

func wireFiles(sys *system) error {
	sys.realtime.Mount(sys.files.Routes()...)
	sys.edge.Mux().HandleFunc(files.HandoffPath, sys.files.HandoffHTTP)
	sys.realtime.OnOpen(func(p protocol.Peer) { sys.fileSources.PeerOpened(p.Principal().UserID, p.ID()) })
	sys.realtime.OnClose(func(p protocol.Peer) {
		sys.files.PeerClosed(files.Caller{P: p.Principal(), Peer: p.ID()})
	})
	// A revocation closes the file sources of the session at once, held
	// ones too, and drops its parked answers (K6).
	unsubscribe := sys.sessions.Subscribe(func(rev principal.Revocation) {
		sys.fileSources.Revoke(rev)
		sys.files.Revoke(rev)
	})
	sys.closers = append(sys.closers, func() error { unsubscribe(); return nil })
	return nil
}

// fileSweepInterval is how often idle SMB sources are looked for.
const fileSweepInterval = 30 * time.Second

func sweepFileSources(ctx context.Context, sys *system) {
	sys.background.Go(func() {
		sys.every(ctx, fileSweepInterval, func(context.Context) bool { sys.fileSources.Sweep(); return true })
	})
}

// The providers that exist already satisfy the consumer interfaces of
// the area.
var (
	_ files.Audit  = (*audit.Logger)(nil)
	_ files.Quotas = (*quota.Policy)(nil)
)
