package main

import (
	"context"
	"time"

	"github.com/bifrost0x/webssh/internal/audit"
	"github.com/bifrost0x/webssh/internal/files"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/quota"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
	"github.com/bifrost0x/webssh/internal/transfer"
)

// transfersArea wires the area "transfers" (TR1): transfers (internal/transfer).
// TR1 fills in the hooks; no other package edits this file.
//
// The manager is built after the file area, whose source registry holds
// the sources while a transfer runs. Its HTTP routes are the token-bound
// transfer routes; its realtime types prepare, cancel and copy. A
// revocation cancels the session's transfers, running ones included, and
// a closed realtime connection cancels what it prepared (K6).
func transfersArea() extension {
	return extension{name: "transfers", wire: wireTransfers}
}

// transferShutdown bounds the wait for running transfers on shutdown.
const transferShutdown = 10 * time.Second

func wireTransfers(sys *system) error {
	limits := transfer.DefaultLimits
	t := sys.cfg.Files.Transfers
	limits.MaxUpload, limits.MaxDownload, limits.MaxArchive = t.MaxUpload, t.MaxDownload, t.MaxArchive
	limits.MaxMembers = sys.cfg.Files.MaxTransferMembers
	if q, ok := sys.cfg.Quotas[quota.TempBytes]; ok {
		limits.TempBytesPerUse = q.PerUser
	}
	reg := sys.fileSources
	m := transfer.New(transfer.Options{
		Sources: reg, Quotas: sys.quotas, Events: transfer.NotifyEvents(sys.realtime.NotifyUser),
		Describe: func(userID int64, session, sourceID string) (files.Descriptor, bool) {
			d, _, err := reg.Describe(principal.Principal{UserID: userID, SessionID: session}, sourceID)
			return d, err == nil
		},
		Audit: sys.audit, Charge: func(userID int64, n int) error {
			return sys.files.ChargeRequest(files.Caller{P: principal.Principal{UserID: userID}}, n)
		},
		Limits: limits, BasePath: sys.cfg.ApplicationRoot, Logger: sys.log,
	})
	sys.transfers = m
	sys.realtime.Mount(m.Routes()...)
	mux := sys.edge.Mux()
	mux.HandleFunc(transfer.RouteDownload, m.DownloadHTTP)
	mux.HandleFunc(transfer.RouteFolderDownload, m.FolderHTTP)
	mux.HandleFunc(transfer.RouteUpload, m.UploadHTTP)
	if err := sys.edge.StreamBody(transfer.RouteUpload); err != nil {
		return err
	}
	sys.realtime.OnOpen(func(p protocol.Peer) { m.PeerOpened(p.Principal().UserID, p.ID()) })
	sys.realtime.OnClose(func(p protocol.Peer) { m.PeerClosed(p.Principal().UserID, p.ID()) })
	unsubscribe := sys.sessions.Subscribe(m.Revoke)
	sys.closers = append(sys.closers, func() error {
		unsubscribe()
		ctx, cancel := context.WithTimeout(context.Background(), transferShutdown)
		defer cancel()
		return m.Shutdown(ctx)
	})
	return nil
}

// The providers that exist already satisfy the consumer interfaces of
// the area.
var (
	_ transfer.Sources = (*files.Registry)(nil)
	_ transfer.Quotas  = (*quota.Policy)(nil)
	_ transfer.Audit   = (*audit.Logger)(nil)
)
