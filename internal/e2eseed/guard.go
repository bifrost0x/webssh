package e2eseed

import (
	"context"
	"net"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/netpolicy"
)

// GuardDialer is the counterpart of the outbound_ssh_guard hook: it takes
// the place of the network dialer of the SSH client and refuses every
// connection with the seed's text, so no browser case reaches the network.
// It satisfies client.NetDialer.
type GuardDialer struct {
	message string
	// allow is the address of the automation peer, the one host the suite
	// may reach.
	allow string
}

// Guard returns the dialer of the outbound_ssh_guard hook, or nil when the
// seed does not enable it.
func (s *Seed) Guard() *GuardDialer {
	for _, h := range s.TestHooks {
		if h.Name == HookOutboundSSHGuard {
			return &GuardDialer{message: h.Error}
		}
	}
	return nil
}

// DialContext refuses the connection. The text comes from the seed,
// which Validate limits to a short printable string, so it is safe to show.
func (g *GuardDialer) DialContext(ctx context.Context, role netpolicy.Role, network, addr string) (net.Conn, error) {
	if g.allow != "" && addr == g.allow && role == netpolicy.RoleSSH {
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
	return nil, fault.Wrap(fault.Unreachable, &net.OpError{Op: "dial", Net: network, Err: errGuarded{role: role, addr: addr}}, g.message)
}

// Allow lets the guard pass connections to the automation peer.
func (g *GuardDialer) Allow(p *AutomationPeer) *GuardDialer {
	if g != nil && p != nil {
		g.allow = p.Addr()
	}
	return g
}

type errGuarded struct {
	role netpolicy.Role
	addr string
}

func (e errGuarded) Error() string {
	return "e2e outbound guard refused " + string(e.role) + " connection to " + e.addr
}
