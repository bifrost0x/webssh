// Package terminal runs interactive shells: sessions with output flow
// control, the input budget, attach and replay after reconnects, host-key
// and banner prompts, idle timeouts and persistent display names. It
// registers the terminal and prompt message types of the realtime protocol
// and provides client.Interaction for each connection attempt.
package terminal

import (
	"context"

	"github.com/bifrost0x/webssh/internal/ssh/client"
)

// Profiles resolves saved hosts for terminal.open (provided by
// internal/hosts). It fails with fault.NotFound for a profile that does not
// exist or belongs to another user, and with fault.NotAvailableInPreview
// for a profile that needs something M1 does not build (saved credentials,
// SOCKS with login, Tailscale, gateway).
type Profiles interface {
	Resolve(ctx context.Context, owner int64, profileID string) (client.Target, error)
}

// Shells opens interactive shells. *client.Dialer provides it; tests use
// a fake shell. OpenShell blocks through the whole attempt, including the
// prompts sent through ix, and fails with a fault code from the SSH
// catalog. Closing the returned shell also closes its connection.
type Shells interface {
	OpenShell(ctx context.Context, t client.Target, ix client.Interaction, rows, cols int) (client.Shell, error)
}
