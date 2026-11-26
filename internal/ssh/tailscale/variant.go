package tailscale

import (
	"context"
	"net"

	"golang.org/x/crypto/ssh"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/netpolicy"
	"github.com/bifrost0x/webssh/internal/ssh/client"
)

// errNoneRefused ends a Tailscale SSH login that the target did not accept
// with "none": tailssh refused the node, or the target is not tailssh. No
// other method is tried, since no credential exists for it.
var errNoneRefused = fault.New(fault.AuthFailed, "Tailscale SSH did not accept this node for the remote user")

// dialInterface is netpolicy.DialInterface; tests replace it.
var dialInterface = netpolicy.DialInterface

// Variant is the dialer variant of the authorized connection: the target
// hop is reached at the pinned address with the socket bound to the
// tailnet interface, and it authenticates with the SSH "none" method only
// (TailscaleSSHAuthStrategy of the Python release). Host keys are checked
// as for every host. A hop that is not the authorized one is refused.
func (a Authorization) Variant() *client.Variant {
	return &client.Variant{
		Auth: func(client.AuthRequest) ssh.ClientAuthCallback {
			return func(*ssh.ClientAuthContext) (ssh.AuthMethod, error) { return nil, errNoneRefused }
		},
		Dial: func(ctx context.Context, h client.Hop) (net.Conn, error) {
			if !a.addr.IsValid() || h.Host != a.host || h.Port != a.port || h.User != a.remoteUser {
				return nil, ErrAuthorizationGone
			}
			conn, err := dialInterface(ctx, a.iface, a.addr)
			if err != nil {
				return nil, fault.Wrap(fault.Unreachable, err, "")
			}
			return conn, nil
		},
	}
}
