package sftp

import (
	"context"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
	"github.com/bifrost0x/webssh/internal/ssh/client"
)

// Quick SFTP through an SSH gateway selector (C-GW-02,
// _start_gateway_quick_connect): the page that answers the gateway's
// prompts (gateway_interaction) asks with a request id; the attempt asks
// on that page under the id and can be cancelled until it produced its
// source. Tailscale SSH, jump hosts and SOCKS5 proxies are refused, as in
// the Python release.

var errGatewayRoute = fault.New(fault.InvalidRequest, "Unsupported gateway client or route")

type quickKey struct {
	peer      uint64
	requestID string
}

type quickAttempt struct {
	owner     int64
	cancel    context.CancelFunc
	committed bool
	cancelled bool
}

// gatewayTarget prepares t when it needs the gateway; an ordinary target
// is returned unchanged with ctx. The caller runs the attempt in the
// returned context and calls end once it is over.
func (a *Area) gatewayTarget(ctx context.Context, peer protocol.Peer, req protocol.FilesQuickOpen, interactive bool,
	t client.Target) (client.Target, context.Context, func(), error) {
	if !a.Connector.NeedsVariant(t) {
		return t, ctx, func() {}, nil
	}
	if t.Display.Tailscale || !interactive || req.ClientRequestID == "" || len(t.Jumps) > 0 || t.Proxy != nil {
		return client.Target{}, nil, nil, errGatewayRoute
	}
	k := quickKey{peer: peer.ID(), requestID: req.ClientRequestID}
	cctx, cancel := context.WithCancel(ctx)
	a.mu.Lock()
	if a.quick[k] != nil {
		a.mu.Unlock()
		cancel()
		return client.Target{}, nil, nil, fault.New(fault.Conflict, "Connection request already in progress")
	}
	if a.quick == nil {
		a.quick = map[quickKey]*quickAttempt{}
	}
	att := &quickAttempt{owner: peer.Principal().UserID, cancel: cancel}
	a.quick[k] = att
	a.mu.Unlock()
	forget := func() {
		a.mu.Lock()
		if a.quick[k] == att {
			delete(a.quick, k)
		}
		a.mu.Unlock()
		cancel()
	}
	vt, vctx, end, err := a.Connector.PrepareFiles(cctx, peer, req.ClientRequestID, t)
	if err != nil {
		forget()
		return client.Target{}, nil, nil, err
	}
	return vt, vctx, func() { end(); forget() }, nil
}

// commitQuick marks the gateway attempt of peer as done, so a cancel
// that comes later is refused; it reports false when the attempt was
// cancelled first (commit_if_active).
func (a *Area) commitQuick(peer protocol.Peer, requestID string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	att := a.quick[quickKey{peer: peer.ID(), requestID: requestID}]
	if att == nil {
		// An ordinary Quick SFTP attempt cannot be cancelled.
		return true
	}
	if att.cancelled {
		return false
	}
	att.committed = true
	return true
}

// quickCancel is ssh_gateway_quick_cancel: not_found without a running
// attempt of the caller on this connection, conflict once the source
// exists.
func (a *Area) quickCancel(ctx context.Context, peer protocol.Peer, req protocol.FilesQuickCancel) (*protocol.Empty, error) {
	p, err := principal.Require(ctx)
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	att := a.quick[quickKey{peer: peer.ID(), requestID: req.ClientRequestID}]
	switch {
	case att == nil || att.owner != p.UserID || att.cancelled:
		return nil, fault.New(fault.NotFound, "")
	case att.committed:
		return nil, fault.New(fault.Conflict, "The connection was already established.")
	}
	att.cancelled = true
	att.cancel()
	return nil, nil
}
