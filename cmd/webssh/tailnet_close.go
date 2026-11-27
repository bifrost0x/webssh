package main

import (
	"context"
	"net/netip"
	"time"

	"github.com/bifrost0x/webssh/internal/ssh/client"
)

// tailnetCloseTimeout bounds the route and name lookups of one pass. A
// lookup that fails counts as restricted, as for a new connection.
const tailnetCloseTimeout = 30 * time.Second

// closeTailnetRestricted closes the open ordinary connections the tailnet
// block refuses now that the administrator turned it on
// (close_restricted_tailnet_connections): terminal sessions, jump chains
// and gateway connections included, detached like an administrator
// disconnect, and Quick SFTP sources. Tailscale SSH and SMB stay open.
// It does nothing while the rule does not apply.
func closeTailnetRestricted(ctx context.Context, sys *system) {
	if sys.policy == nil || !sys.policy.TailnetRuleActive() {
		return
	}
	// The request may end before the pass does; the pass must not.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), tailnetCloseTimeout)
	defer cancel()
	restricted := func(peer netip.Addr, onward []string) bool {
		return sys.policy.OpenRouteRestricted(ctx, peer, onward)
	}
	sessions, sources := 0, 0
	if sys.terminal != nil {
		sessions = sys.terminal.CloseRestrictedRoutes(func(r client.Route) bool { return restricted(r.Peer, r.Onward) })
	}
	if sys.fileSources != nil {
		sources = sys.fileSources.CloseRestrictedRoutes(restricted)
	}
	sys.audit.Security("TAILNET_RESTRICTED_CONNECTIONS_CLOSED", "ssh_sessions", sessions, "pool_connections", sources, "errors", 0)
}
