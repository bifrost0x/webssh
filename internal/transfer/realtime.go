package transfer

import (
	"context"
	"encoding/json/jsontext"
	"time"

	"github.com/bifrost0x/webssh/internal/files"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
)

// maxControlPayload bounds a request: two paths of up to 4096 bytes,
// escaped, and the ids.
const maxControlPayload = 32 << 10

// Routes returns the realtime routes of transfer.* (docs/architecture/
// m2-contracts.md, "Message types (transfer)").
func (m *Manager) Routes() []protocol.Route {
	spec := protocol.Spec{Async: true, Mutates: true, Timeout: 30 * time.Second, MaxPayload: maxControlPayload}
	return []protocol.Route{
		route(m, protocol.TypeTransferPrepare, spec, m.prepareRoute),
		route(m, protocol.TypeTransferCancel, spec, m.cancelRoute),
		route(m, protocol.TypeTransferCopy, spec, m.copyRoute),
	}
}

// route is protocol.Handle with the byte budget of file requests charged
// before the payload is decoded, as Python's _file_request_identity did.
func route[Req, Resp any](m *Manager, typ string, spec protocol.Spec, h func(context.Context, files.Caller, Req) (Resp, error)) protocol.Route {
	inner := protocol.Handle(typ, spec, func(ctx context.Context, peer protocol.Peer, req Req) (Resp, error) {
		return h(ctx, files.Caller{P: peer.Principal(), Peer: peer.ID()}, req)
	})
	return protocol.Route{Type: typ, Spec: spec, Run: func(ctx context.Context, peer protocol.Peer, p jsontext.Value) (any, error) {
		if m.o.Charge != nil {
			if err := m.o.Charge(peer.Principal().UserID, max(len(p), 256)); err != nil {
				return nil, err
			}
		}
		return inner.Run(ctx, peer, p)
	}}
}

func (m *Manager) prepareRoute(ctx context.Context, c files.Caller, rq protocol.TransferPrepare) (*protocol.TransferPrepared, error) {
	if rq.SourceID == "" || !files.ValidRequestID(rq.RequestID) {
		return nil, errPrepare
	}
	pr, err := m.Prepare(ctx, c, PrepareRequest{
		SourceID: rq.SourceID, Direction: Direction(rq.Direction), Path: rq.RemotePath,
		Archive: rq.Archive, Policy: ConflictPolicy(rq.ConflictPolicy),
	})
	if err != nil {
		return nil, err
	}
	return &protocol.TransferPrepared{
		FileRef: rq.FileRef, TransferID: pr.TransferID, URL: pr.URL, Direction: rq.Direction,
		ExpiresAt: float64(pr.ExpiresAt.UnixMilli()) / 1000,
	}, nil
}

func (m *Manager) cancelRoute(_ context.Context, c files.Caller, rq protocol.TransferCancel) (*protocol.TransferCancelState, error) {
	if rq.TransferID == "" || len(rq.TransferID) > 64 {
		return &protocol.TransferCancelState{State: string(CancelUnavailable)}, nil
	}
	return &protocol.TransferCancelState{State: string(m.CancelFor(c.P.UserID, rq.TransferID))}, nil
}

func (m *Manager) copyRoute(ctx context.Context, c files.Caller, rq protocol.TransferCopy) (*protocol.TransferCopyStarted, error) {
	if !files.ValidRequestID(rq.RequestID) {
		return nil, errMissing
	}
	id, err := m.Copy(ctx, c, CopyRequest{
		SourceID: rq.SourceID, SourcePath: rq.SourcePath, DestID: rq.DestinationSourceID, DestPath: rq.DestPath,
		RequestID: rq.RequestID, Policy: ConflictPolicy(rq.ConflictPolicy),
	})
	if err != nil {
		return nil, err
	}
	return &protocol.TransferCopyStarted{FileRef: rq.FileRef, TransferID: id, DestinationSourceID: rq.DestinationSourceID}, nil
}

// Notifier pushes a server event to every connection of a user
// (realtime.Server.NotifyUser).
type Notifier func(userID int64, typ string, payload any) int

// NotifyEvents returns the Events that send transfer.progress and
// transfer.finished through n.
func NotifyEvents(n Notifier) Events { return notifier(n) }

type notifier Notifier

func copyRef(c *CopyRef) *protocol.TransferCopyRef {
	if c == nil {
		return nil
	}
	return &protocol.TransferCopyRef{SourceID: c.SourceID, RequestID: c.RequestID, DestinationSourceID: c.DestinationSourceID}
}

func (n notifier) Progress(userID int64, ev Progress) {
	n(userID, protocol.TypeTransferProgress, protocol.TransferProgressEvent{
		TransferID: ev.TransferID, Direction: string(ev.Direction), Transferred: ev.Transferred, Total: ev.Total,
		Filename: ev.Filename, Copy: copyRef(ev.Copy),
	})
}

func (n notifier) Finished(userID int64, ev Finished) {
	out := protocol.TransferFinishedEvent{
		TransferID: ev.TransferID, Direction: string(ev.Direction), Status: string(ev.State),
		Copy: copyRef(ev.Copy), Filename: ev.Filename, SourcePath: ev.SourcePath, DestPath: ev.DestPath,
	}
	if f := ev.Failure; f != nil {
		retry := f.Retryable()
		out.ErrorCode, out.Error, out.Retryable = string(f.Code), f.text(), &retry
		if f.LimitKind != "" {
			out.LimitKind, out.LimitBytes = string(f.LimitKind), &f.LimitBytes
			if f.ActualBytes >= 0 {
				out.ActualBytes = &f.ActualBytes
			}
		}
	}
	n(userID, protocol.TypeTransferFinished, out)
}
