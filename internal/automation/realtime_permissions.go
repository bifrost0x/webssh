package automation

import (
	"context"
	"encoding/json/jsontext"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
)

// maxPrepareBody fits PermMaxNameBytes of paths in JSON escapes, as the
// editor body is bounded.
const maxPrepareBody = 6*PermMaxNameBytes + 64<<10

// Routes returns the realtime routes of permissions.* (docs/architecture/
// m2-contracts.md, "Message types (permissions)").
func (j *PermissionJobs) Routes() []protocol.Route {
	spec := func(timeout time.Duration, mutates bool, payload int) protocol.Spec {
		return protocol.Spec{Async: true, Timeout: timeout, Mutates: mutates, MaxPayload: payload}
	}
	const small = 32 << 10
	return []protocol.Route{
		permRoute(protocol.TypePermissionsGet, spec(30*time.Second, false, small), j.getRoute),
		permRoute(protocol.TypePermissionsSet, spec(60*time.Second, true, small), j.setRoute),
		permRoute(protocol.TypePermissionsJobPrepare, spec(30*time.Second, true, maxPrepareBody), j.prepareRoute),
		permRoute(protocol.TypePermissionsJobGet, spec(30*time.Second, false, small), j.jobRoute(j.Get)),
		permRoute(protocol.TypePermissionsJobApply, spec(30*time.Second, true, small), j.jobRoute(j.Apply)),
		permRoute(protocol.TypePermissionsJobCancel, spec(30*time.Second, false, small), j.jobRoute(j.Cancel)),
	}
}

func permRoute[Req any](typ string, spec protocol.Spec, h func(context.Context, PermCaller, Req) (jsontext.Value, error)) protocol.Route {
	return protocol.Handle(typ, spec, func(ctx context.Context, peer protocol.Peer, req Req) (jsontext.Value, error) {
		out, err := h(ctx, PermCaller{P: peer.Principal(), Peer: peer.ID()}, req)
		return out, permFault(err)
	})
}

// permFault answers with the text of the Python release for the code; the
// details (actual_mode) stay.
func permFault(err error) error {
	if err == nil {
		return nil
	}
	code := fault.CodeOf(err)
	if code == "" || code == fault.Internal {
		code = fault.OperationFailed
	}
	message := fileMessage(code)
	if code == fault.SourceUnavailable {
		message = "File source unavailable"
	}
	out := fault.Wrap(code, err, message)
	out.Details = fault.DetailsOf(err)
	return out
}

func requireFileRef(r protocol.FileRef) error {
	if r.SourceID == "" || r.RequestID == "" || len(r.RequestID) > 128 {
		return fault.New(fault.InvalidRequest, "")
	}
	return nil
}

func (j *PermissionJobs) getRoute(ctx context.Context, c PermCaller, rq protocol.PermissionsGet) (jsontext.Value, error) {
	if err := requireFileRef(rq.FileRef); err != nil {
		return nil, err
	}
	return j.Inspect(ctx, c, rq.SourceID, rq.Path)
}

func (j *PermissionJobs) setRoute(ctx context.Context, c PermCaller, rq protocol.PermissionsSet) (jsontext.Value, error) {
	if err := requireFileRef(rq.FileRef); err != nil {
		return nil, err
	}
	return j.Change(ctx, c, rq.SourceID, rq.Path, rq.Mode, rq.ExpectedMetadata)
}

func (j *PermissionJobs) prepareRoute(ctx context.Context, c PermCaller, rq protocol.PermissionsJobPrepare) (jsontext.Value, error) {
	if err := requireFileRef(rq.FileRef); err != nil {
		return nil, err
	}
	return j.Prepare(ctx, c, PermRequest{SourceID: rq.SourceID, Paths: rq.Paths, Recursive: rq.Recursive,
		FileMode: rq.FileMode, DirMode: rq.DirectoryMode})
}

func (j *PermissionJobs) jobRoute(op func(context.Context, PermCaller, string, string) (jsontext.Value, error)) func(context.Context, PermCaller, protocol.PermissionsJob) (jsontext.Value, error) {
	return func(ctx context.Context, c PermCaller, rq protocol.PermissionsJob) (jsontext.Value, error) {
		if err := requireFileRef(rq.FileRef); err != nil {
			return nil, err
		}
		return op(ctx, c, rq.SourceID, rq.JobID)
	}
}
