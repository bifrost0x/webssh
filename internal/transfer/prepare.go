package transfer

import (
	"context"
	"path"
	"strings"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/files"
)

// PrepareRequest asks for an HTTP transfer (prepare_transfer).
type PrepareRequest struct {
	SourceID  string
	Direction Direction // Upload or Download
	Path      string    // the file, the folder (Archive) or the upload target
	Archive   bool
	Policy    ConflictPolicy // "" is ConflictError
}

// Prepared is a transfer waiting for its HTTP request.
type Prepared struct {
	TransferID string
	URL        string // below the application root
	ExpiresAt  time.Time
}

var errPrepare = fault.New(fault.TransferUnavailable, "Transfer unavailable")

// Prepare checks the source, the path and the quota and returns the
// one-use URL of the transfer. The source stays held until the transfer
// ends. Every refusal is the same TRANSFER_UNAVAILABLE, as in Python.
func (m *Manager) Prepare(ctx context.Context, c files.Caller, rq PrepareRequest) (Prepared, error) {
	policy := cmpPolicy(rq.Policy)
	need := files.CapRead
	var clean func(string) (string, error) = files.Clean
	switch {
	case policy == "":
		return Prepared{}, errPrepare
	case rq.Direction == Upload && !rq.Archive:
		need, clean = files.CapWrite, files.CleanTarget
	case rq.Direction == Download && policy == ConflictError:
		if rq.Archive {
			need |= files.CapRecursive
		}
	default:
		return Prepared{}, errPrepare
	}
	p, err := clean(rq.Path)
	if err != nil {
		return Prepared{}, errPrepare
	}
	_, hold, err := m.o.Sources.Resolve(ctx, c.P, rq.SourceID, need)
	if err != nil {
		return Prepared{}, errPrepare
	}
	r := &record{
		owner: principalKey{c.P.UserID, c.P.SessionID}, peer: c.Peer, direction: rq.Direction,
		archive: rq.Archive, sourceID: rq.SourceID, path: p, policy: policy,
	}
	token, err := m.create(ctx, r, []func(){hold})
	if err != nil {
		m.o.Logger.Debug("transfer preparation refused", "user_id", c.P.UserID, "code", fault.CodeOf(err))
		return Prepared{}, errPrepare
	}
	route := "download"
	switch {
	case rq.Direction == Upload:
		route = "upload"
	case rq.Archive:
		route = "folder-download"
	}
	return Prepared{
		TransferID: r.id, URL: m.o.BasePath + "/api/transfers/" + token + "/" + route,
		ExpiresAt: r.started.Add(m.o.TokenTTL),
	}, nil
}

// cmpPolicy returns the policy, ConflictError for none, "" for an
// unknown one.
func cmpPolicy(p ConflictPolicy) ConflictPolicy {
	switch p {
	case "", ConflictError:
		return ConflictError
	case ConflictReplace:
		return ConflictReplace
	}
	return ""
}

// CopyRequest starts a host-to-host copy (transfer_server_to_server).
type CopyRequest struct {
	SourceID, SourcePath string
	DestID, DestPath     string
	RequestID            string
	Policy               ConflictPolicy
}

var (
	errMissing     = fault.New(fault.InvalidRequest, "Missing required fields")
	errInvalidPath = fault.New(fault.InvalidRequest, "Invalid path")
)

// Copy starts a copy between two sources of the caller's browser session
// in the background and returns its id. Its progress and outcome reach
// the user's connections as events; a failure before the start is the
// public failure itself.
func (m *Manager) Copy(ctx context.Context, c files.Caller, rq CopyRequest) (string, error) {
	policy := cmpPolicy(rq.Policy)
	if policy == "" || rq.SourceID == "" || rq.DestID == "" || rq.SourcePath == "" || rq.DestPath == "" {
		return "", errMissing
	}
	from, errA := files.Clean(rq.SourcePath)
	to, errB := files.CleanTarget(rq.DestPath)
	if errA != nil || errB != nil {
		return "", errInvalidPath
	}
	src, holdA, err := m.o.Sources.Resolve(ctx, c.P, rq.SourceID, files.CapRead|files.CapRemoteTransfer)
	if err != nil {
		return "", newFailure(fault.SourceUnavailable, opCopy).asFault()
	}
	dst, holdB, err := m.o.Sources.Resolve(ctx, c.P, rq.DestID, files.CapWrite|files.CapRemoteTransfer)
	if err != nil {
		holdA()
		return "", newFailure(fault.SourceUnavailable, opCopy).asFault()
	}
	release := []func(){holdA, holdB}
	job, err := m.o.Quotas.Reserve(ctx, quotaJob, c.P.UserID, 1)
	if err != nil {
		runAll(release)
		return "", newFailure(fault.TransferUnavailable, opCopy).asFault()
	}
	ref := &CopyRef{SourceID: rq.SourceID, RequestID: rq.RequestID, DestinationSourceID: rq.DestID}
	r := &record{
		owner: principalKey{c.P.UserID, c.P.SessionID}, peer: c.Peer, direction: ServerToServer,
		sourceID: rq.SourceID, path: from, destID: rq.DestID, destPath: to, policy: policy, copy: ref,
	}
	runCtx, cancel := context.WithCancelCause(m.base)
	r.cancel = cancel
	if _, err := m.create(ctx, r, append(release, job)); err != nil {
		cancel(nil)
		return "", newFailure(fault.TransferUnavailable, opCopy).asFault()
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		m.finish(r, Cancelled, nil, false)
		cancel(nil)
		return "", newFailure(fault.TransferUnavailable, opCopy).asFault()
	}
	m.work.Add(1)
	m.mu.Unlock()
	go m.runCopy(runCtx, c, r, src, dst)
	return r.id, nil
}

func baseName(p string) string {
	if b := path.Base(strings.TrimRight(p, "/")); b != "." && b != "" && b != "/" {
		return b
	}
	return "/"
}
