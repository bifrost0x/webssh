package client

import (
	"context"
	"net"

	"golang.org/x/crypto/ssh"
)

// Variant changes how a connection is authenticated, reached or confirmed,
// for the SSH gateway and Tailscale SSH (D-22: one dialer, variants by
// options). The packages internal/ssh/gateway and internal/ssh/tailscale
// build it; nil is an ordinary connection. Host keys and, except for Dial,
// the network policy apply to every variant unchanged.
type Variant struct {
	// Auth replaces the authentication plan of every SSH hop, jump hosts
	// included. It is called once per hop and returns the callback x/crypto
	// asks before each method. With Auth set, the target hop needs no
	// password or key.
	Auth func(AuthRequest) ssh.ClientAuthCallback
	// Dial opens the TCP connection to the target hop in place of the
	// network policy (Tailscale SSH: the address pinned by the
	// authorization, bound to the tailnet interface). A target with Dial
	// has no jump hosts and no proxy.
	Dial func(ctx context.Context, h Hop) (net.Conn, error)
	// Ready runs on the authenticated target before Dial returns (the
	// gateway's readiness probe). An error closes the connection.
	Ready func(ctx context.Context, target *ssh.Client) error
}

// AuthRequest is what Variant.Auth gets for one hop.
type AuthRequest struct {
	// Ctx is the hop's context; it ends with the handshake.
	Ctx      context.Context
	Role     Role
	Host     string
	Port     int
	User     string
	Password string
	// Guard re-checks a saved Password; the variant runs it right before
	// the password is sent and ends the attempt on an error. Nil for a
	// typed password.
	Guard PasswordGuard
	// Signer is the hop's stored key, nil without one.
	Signer ssh.Signer
	// Pause stops the handshake watchdog while the user is asked; call the
	// returned function once the answer is in.
	Pause func() (resume func())
}

func (t Target) authVariant() func(AuthRequest) ssh.ClientAuthCallback {
	if t.Variant == nil {
		return nil
	}
	return t.Variant.Auth
}

func (t Target) dialVariant() func(context.Context, Hop) (net.Conn, error) {
	if t.Variant == nil {
		return nil
	}
	return t.Variant.Dial
}
