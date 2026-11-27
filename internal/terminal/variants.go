package terminal

import (
	"context"
	"strings"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
	"github.com/bifrost0x/webssh/internal/ssh/client"
)

// Variants prepares the SSH gateway and Tailscale SSH forms of a
// connection attempt (provided by cmd/webssh over internal/ssh/gateway and
// internal/ssh/tailscale). Without it both are refused as not available.
type Variants interface {
	// Prepare is called once per attempt after the target is resolved, for
	// a gateway selector (the username contains ":") or a Tailscale SSH
	// host (Display.Tailscale). It returns the target with its Variant set,
	// the context the attempt must run in (it ends with ctx at the latest)
	// and end, which releases the attempt's state and is called once the
	// attempt is over, whatever its outcome. A refusal carries a fault code
	// and a text that is safe to show.
	Prepare(ctx context.Context, a VariantAttempt) (client.Target, context.Context, func(), error)
	// Interact is called once per attempt of an ordinary connection whose
	// page answers prompt.interactive (Interactive). It returns the
	// client.Challenger that puts the keyboard-interactive rounds the
	// dialer cannot answer to that page (C-CONN-09), with the attempt's
	// context and end as for Prepare.
	Interact(ctx context.Context, a VariantAttempt) (client.Challenger, context.Context, func(), error)
}

// VariantAttempt is one connection attempt that needs a variant.
type VariantAttempt struct {
	// Peer is the connection that asked; prompts go to it only.
	Peer      protocol.Peer
	User      principal.Principal
	RequestID string
	// Interactive is terminal.open's interactive flag: the page answers
	// prompt.interactive and shows the gateway's temporary terminal.
	Interactive bool
	// Files marks a file connection (Quick SFTP): no temporary terminal
	// and no Tailscale SSH, as in the Python release.
	Files  bool
	Target client.Target
}

// needsVariant reports a target only a Variants provider can connect.
func needsVariant(t client.Target) bool {
	return t.Display.Tailscale || strings.Contains(t.Hop.User, ":")
}

// prepareVariant runs the provider for a target that needs it. Without a
// provider such a target is not available in this build. An ordinary
// target whose page answers prompts gets the provider's challenger, so
// the user can answer further keyboard-interactive rounds; without a
// provider those rounds stay not available.
func (m *Manager) prepareVariant(ctx context.Context, peer protocol.Peer, p principal.Principal,
	req protocol.TerminalOpen, t client.Target) (client.Target, context.Context, func(), client.Challenger, error) {
	a := VariantAttempt{Peer: peer, User: p, RequestID: req.RequestID, Interactive: req.Target.Interactive, Target: t}
	if !needsVariant(t) {
		if !a.Interactive || m.variants == nil || req.RequestID == "" {
			return t, ctx, func() {}, nil, nil
		}
		ch, ictx, end, err := m.variants.Interact(ctx, a)
		if err != nil {
			return client.Target{}, nil, nil, nil, err
		}
		return t, ictx, end, ch, nil
	}
	if m.variants == nil {
		return client.Target{}, nil, nil, nil, fault.New(fault.NotAvailableInPreview, "")
	}
	t, vctx, end, err := m.variants.Prepare(ctx, a)
	return t, vctx, end, nil, err
}

// NeedsVariant reports a target that only connects through the SSH
// gateway or Tailscale SSH.
func NeedsVariant(t client.Target) bool { return needsVariant(t) }

// PrepareFiles prepares the gateway form of a file connection of p on
// peer (Quick SFTP through a gateway selector), with the same provider as
// terminal.open: the prompts go to peer under requestID. The returned
// context and end are those of Variants.Prepare.
func (m *Manager) PrepareFiles(ctx context.Context, peer protocol.Peer, requestID string, t client.Target) (client.Target, context.Context, func(), error) {
	if m.variants == nil {
		return client.Target{}, nil, nil, fault.New(fault.NotAvailableInPreview, "")
	}
	return m.variants.Prepare(ctx, VariantAttempt{Peer: peer, User: peer.Principal(), RequestID: requestID,
		Interactive: true, Files: true, Target: t})
}

// challengingInteraction is the attempt's interaction with the rounds of
// keyboard-interactive put to the page as well.
type challengingInteraction struct {
	client.Interaction
	client.Challenger
}

// typedVariant resolves the typed parts of a gateway selector or a
// Tailscale SSH connection; the provider checks the rest. ok is false for
// an ordinary connection.
func (m *Manager) typedVariant(req protocol.OpenTarget, host, user string, port int, owner int64) (client.Target, bool, error) {
	tailscale := req.AuthType == protocol.AuthTailscale
	gateway := strings.Contains(user, ":")
	if !tailscale && !gateway {
		return client.Target{}, false, nil
	}
	if m.variants == nil {
		return client.Target{}, true, fault.New(fault.NotAvailableInPreview, "")
	}
	switch {
	case tailscale && gateway:
		return client.Target{}, true, invalid("Gateway selectors cannot use Tailscale SSH")
	case tailscale && req.JumpHostID != "":
		return client.Target{}, true, invalid("Tailscale SSH cannot be used with a jump host")
	case tailscale && req.SOCKSProxyID != "":
		return client.Target{}, true, invalid("Tailscale SSH cannot be used with a SOCKS5 proxy")
	case tailscale && !usernamePattern.MatchString(user):
		return client.Target{}, true, invalid("Invalid username format.")
	case req.AuthType == protocol.AuthKey && req.KeyID == "":
		return client.Target{}, true, invalid("Password or SSH key required.")
	}
	t := client.Target{Owner: owner, Hop: client.Hop{Host: host, Port: port, User: user}}
	switch req.AuthType {
	case protocol.AuthTailscale:
		t.Display.Tailscale = true
	case protocol.AuthKey:
		t.Hop.Auth.KeyID = req.KeyID
	default:
		// A gateway may ask for the password itself; it can be empty.
		t.Hop.Auth.Password = req.Password
	}
	return t, true, nil
}
