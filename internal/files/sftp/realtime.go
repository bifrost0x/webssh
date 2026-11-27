package sftp

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/files"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
	"github.com/bifrost0x/webssh/internal/ssh/client"
)

// Rate-limit buckets of the Python handlers.
const (
	RateConnect    = "ssh_connect"             // RATELIMIT_SSH_CONNECT, shared with the terminal
	RateProbe      = "session_sftp_capability" // CAPABILITY_RATE_LIMIT
	RateDirectory  = "session_directory"
	quickPayload   = 32 << 10
	maxIdentifier  = 128
	quickCloseWait = 30 * time.Second
)

// Connector is the terminal side of Quick SFTP (internal/terminal through
// cmd/webssh): it checks and resolves the typed or saved target like
// terminal.open, saved passwords included, and asks the user about host
// keys and banners with the prompts of the terminal (D-22).
type Connector interface {
	Target(ctx context.Context, owner int64, req protocol.OpenTarget) (client.Target, error)
	Interaction(peer protocol.Peer, requestID string) client.Interaction
}

// Registry is the file source registry (internal/files).
type Registry interface {
	Reserve(ctx context.Context, p principal.Principal, kind files.SourceKind) (*files.Slot, error)
	Describe(p principal.Principal, sourceID string) (files.Descriptor, files.Capabilities, error)
	Close(p principal.Principal, sourceID string) error
}

// Area serves the realtime types of the SFTP sources.
type Area struct {
	Quick     *Quick
	Registry  Registry
	Connector Connector
	Sessions  Sessions

	mu      sync.Mutex
	probing map[string]bool // sessions with a directory probe running
}

// Routes are the files.quick.* and files.session.* types.
func (a *Area) Routes() []protocol.Route {
	open := protocol.Spec{Async: true, Mutates: true, RateKey: RateConnect, MaxPayload: quickPayload,
		Timeout: 5 * time.Minute}
	return []protocol.Route{
		protocol.Handle(protocol.TypeFilesQuickOpen, open, a.quickOpen),
		protocol.Handle(protocol.TypeFilesQuickClose, protocol.Spec{Mutates: true, Timeout: quickCloseWait}, a.quickClose),
		protocol.Handle(protocol.TypeFilesSessionProbe, protocol.Spec{Async: true, RateKey: RateProbe, Timeout: 2 * ProbeTimeout}, a.probe),
		protocol.Handle(protocol.TypeFilesSessionDirectory, protocol.Spec{Async: true, RateKey: RateDirectory, Timeout: 2 * DirectoryTimeout}, a.directory),
	}
}

// errQuota is the answer of the Python pool when the user has too many
// quick connections.
var errQuota = fault.New(fault.Busy, "Maximum number of quick connections reached")

func (a *Area) quickOpen(ctx context.Context, peer protocol.Peer, req protocol.FilesQuickOpen) (protocol.FilesQuickOpened, error) {
	p, err := principal.Require(ctx)
	if err != nil {
		return protocol.FilesQuickOpened{}, err
	}
	if len(req.ClientRequestID) > maxIdentifier {
		return protocol.FilesQuickOpened{}, fault.New(fault.InvalidRequest, "")
	}
	// Persistent sessions and the gateway's temporary terminal belong to
	// the terminal; Quick SFTP is one file source.
	req.UseTmux, req.TmuxSessionName, req.Interactive = false, "", false
	t, err := a.Connector.Target(ctx, p.UserID, req.OpenTarget)
	if err != nil {
		return protocol.FilesQuickOpened{}, err
	}
	if t.Variant != nil {
		// Quick SFTP through the SSH gateway or Tailscale SSH (C-GW-02).
		return protocol.FilesQuickOpened{}, fault.New(fault.NotAvailableInPreview, "")
	}
	slot, err := a.Registry.Reserve(ctx, p, files.SourceSFTPQuick)
	if err != nil {
		if fault.Is(err, fault.Busy) {
			err = errQuota
		}
		return protocol.FilesQuickOpened{}, err
	}
	d, b, err := a.Quick.Open(ctx, p, t, a.Connector.Interaction(peer, req.ClientRequestID))
	if err != nil {
		slot.Release()
		return protocol.FilesQuickOpened{}, err
	}
	if peer.Context().Err() != nil {
		slot.Release()
		_ = b.Close()
		return protocol.FilesQuickOpened{}, fault.New(fault.Cancelled, "")
	}
	id, err := slot.Add(d, b)
	if err != nil {
		return protocol.FilesQuickOpened{}, err
	}
	d, caps, err := a.Registry.Describe(p, id)
	if err != nil {
		return protocol.FilesQuickOpened{}, err
	}
	_, handle, _ := files.ParseSourceID(id)
	return protocol.FilesQuickOpened{
		ClientRequestID: req.ClientRequestID, ConnectionID: handle, Host: t.Hop.Host, Port: t.Hop.Port,
		Username: t.Hop.User, FileSource: files.PublicSource(d, caps),
	}, nil
}

func (a *Area) quickClose(ctx context.Context, _ protocol.Peer, req protocol.FilesQuickClose) (protocol.FilesQuickClosed, error) {
	p, err := principal.Require(ctx)
	if err != nil {
		return protocol.FilesQuickClosed{}, err
	}
	if req.ConnectionID == "" {
		return protocol.FilesQuickClosed{}, fault.New(fault.InvalidRequest, "Connection ID required")
	}
	id, err := files.FormatSourceID(files.SourceSFTPQuick, req.ConnectionID)
	if err == nil {
		err = a.Registry.Close(p, id)
	}
	if err != nil {
		return protocol.FilesQuickClosed{}, fault.New(fault.SourceUnavailable, "Unauthorized access to connection")
	}
	return protocol.FilesQuickClosed(req), nil
}

func validIdentifier(s string) bool { return s != "" && len(s) <= maxIdentifier }

func (a *Area) probe(ctx context.Context, _ protocol.Peer, req protocol.FilesSessionProbe) (protocol.FilesSessionCapability, error) {
	p, err := principal.Require(ctx)
	if err != nil {
		return protocol.FilesSessionCapability{}, err
	}
	if !validIdentifier(req.SessionID) || !validIdentifier(req.RequestID) {
		return protocol.FilesSessionCapability{}, fault.New(fault.InvalidRequest, "")
	}
	out := protocol.FilesSessionCapability{SessionID: req.SessionID, RequestID: req.RequestID}
	sess, err := a.Sessions.Session(ctx, p, req.SessionID)
	if err != nil {
		return out, fault.New(fault.SourceUnavailable, "")
	}
	switch err := Probe(ctx, sess.Conn, a.Quick.Options); {
	case err == nil:
		out.Available = true
	case fault.Is(err, fault.ChannelRejected):
		return out, err
	case errors.Is(err, context.Canceled):
		return out, err
	}
	// Any other failure means the session has no browsable SFTP.
	return out, nil
}

func (a *Area) directory(ctx context.Context, _ protocol.Peer, req protocol.FilesSessionDirectoryRequest) (protocol.FilesSessionDirectory, error) {
	p, err := principal.Require(ctx)
	if err != nil {
		return protocol.FilesSessionDirectory{}, err
	}
	reason := func(r string) (protocol.FilesSessionDirectory, error) {
		return protocol.FilesSessionDirectory{Reason: &r}, nil
	}
	if !validIdentifier(req.SessionID) {
		return reason("unavailable")
	}
	sess, err := a.Sessions.Session(ctx, p, req.SessionID)
	if err != nil || sess.Exec == nil {
		return reason("unavailable")
	}
	if !a.begin(req.SessionID) {
		return reason("busy")
	}
	defer a.end(req.SessionID)
	d, err := CollectDirectory(ctx, sess.Exec, sess.Tmux)
	switch {
	case errors.Is(err, ErrDirectoryUnsupported):
		return reason("unsupported")
	case err != nil:
		return reason("unavailable")
	}
	// Read after the probe, as the Python release did: typing during the
	// probe counts.
	out := &protocol.SessionDirectory{Path: d.Path, ShellReady: d.ShellReady, ShellID: d.ShellID, Shell: d.Shell,
		BracketedPaste: d.BracketedPaste, Tmux: sess.Tmux != "", InputIdle: sess.InputIdle != nil && sess.InputIdle()}
	if d.Prompt != nil {
		out.Prompt = &protocol.PromptMarker{Generation: int(d.Prompt.Generation), Phase: d.Prompt.Phase}
	}
	return protocol.FilesSessionDirectory{Directory: out}, nil
}

// begin serializes the probes of one session (directory_probe_lock).
func (a *Area) begin(session string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.probing == nil {
		a.probing = map[string]bool{}
	}
	if a.probing[session] {
		return false
	}
	a.probing[session] = true
	return true
}

func (a *Area) end(session string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.probing, session)
}
