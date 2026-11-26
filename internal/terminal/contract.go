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
// for a profile that needs something this build does not have (Tailscale,
// gateway). Hops that sign in with a password carry none; the terminal adds
// the password of the attempt or the saved one.
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

// SavedPasswords returns the saved password assigned to a resource of
// owner: a saved host "<id>", a jump host "jump:<id>" or a SOCKS5 proxy
// "socks:<id>" (internal/vault through cmd/webssh). It fails with the
// vault's codes (credential_missing, credential_target_changed, ...).
type SavedPasswords interface {
	Password(ctx context.Context, owner int64, resourceID string) (string, error)
}
