package client

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/netpolicy"
)

// Defaults of the dialer. SSH_CONNECT_TIMEOUT is 10 s in the Python release.
const (
	DefaultHandshakeTimeout   = 10 * time.Second
	DefaultInteractionTimeout = 3 * time.Minute
	DefaultKeepalive          = 30 * time.Second
	DefaultMaxJumps           = 4
)

// Dialer opens SSH connections: direct, through a jump-host chain or
// through a SOCKS5 proxy (D-22). Net and HostKeys are required, so every
// connection passes the network policy and the host-key check; Keys is
// required for hops with a stored key.
type Dialer struct {
	Net      Network
	HostKeys HostKeys
	Keys     KeySource

	// HandshakeTimeout bounds the TCP connection, SOCKS5 and every part of
	// a hop's SSH handshake that does not wait for the user.
	HandshakeTimeout time.Duration
	// InteractionTimeout bounds one hop including the user's decisions.
	InteractionTimeout time.Duration
	// Keepalive is the interval of keepalive requests; a peer that does
	// not answer within one interval is disconnected.
	Keepalive time.Duration
	MaxJumps  int
	// RekeyThreshold is the number of bytes after which keys are
	// renewed; 0 is the x/crypto default.
	RekeyThreshold uint64
	Logger         *slog.Logger
}

// hop is a validated hop with everything the handshake needs.
type hop struct {
	Hop
	role   Role
	dest   string // what the previous relay is asked to reach
	signer ssh.Signer
}

func (d *Dialer) defaults() Dialer {
	c := *d
	if c.HandshakeTimeout <= 0 {
		c.HandshakeTimeout = DefaultHandshakeTimeout
	}
	if c.InteractionTimeout <= 0 {
		c.InteractionTimeout = DefaultInteractionTimeout
	}
	if c.Keepalive == 0 {
		c.Keepalive = DefaultKeepalive
	}
	if c.MaxJumps <= 0 {
		c.MaxJumps = DefaultMaxJumps
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	return c
}

func invalid(message string) error {
	return fault.Wrap(fault.InvalidRequest, &HopError{Role: RoleTarget}, message)
}

// Dial connects to the target of t. ix answers host-key and banner prompts;
// nil is unattended. On error nothing stays open.
func (d *Dialer) Dial(ctx context.Context, t Target, ix Interaction) (*Conn, error) {
	cfg := d.defaults()
	hops, err := cfg.prepare(ctx, t)
	if err != nil {
		return nil, err
	}
	conn, err := cfg.firstConn(ctx, t, hops)
	if err != nil {
		return nil, err
	}
	first := conn.RemoteAddr()
	var chain []*ssh.Client
	closeChain := func() {
		for _, c := range slices.Backward(chain) {
			_ = c.Close()
		}
	}
	for i, h := range hops {
		if i > 0 {
			if conn, err = cfg.channelConn(ctx, chain[i-1], h); err != nil {
				closeChain()
				return nil, err
			}
		}
		client, err := cfg.handshake(ctx, conn, t.Owner, h, ix, t.authVariant())
		if err != nil {
			closeChain()
			return nil, err
		}
		chain = append(chain, client)
	}
	c := newConn(chain, cfg.Keepalive, cfg.HandshakeTimeout)
	if t.dialVariant() == nil {
		c.route, c.routed = routeOf(first, t, hops), true
	}
	if t.Variant != nil && t.Variant.Ready != nil {
		if err := t.Variant.Ready(ctx, chain[len(chain)-1]); err != nil {
			_ = c.Close()
			return nil, fail(ctx, RoleTarget, false, err)
		}
	}
	return c, nil
}

// prepare validates t, canonicalizes every host, asks the network policy
// what each relay may be asked to reach and loads the stored keys, all
// before the first packet is sent.
func (d *Dialer) prepare(ctx context.Context, t Target) ([]hop, error) {
	ctx, cancel := context.WithTimeout(ctx, d.HandshakeTimeout)
	defer cancel()
	switch {
	case d.Net == nil || d.HostKeys == nil:
		return nil, invalid("The SSH dialer is not configured.")
	case t.Owner <= 0:
		return nil, invalid("")
	case t.Proxy != nil && len(t.Jumps) > 0:
		return nil, invalid("A host can use either a jump host or a SOCKS5 proxy, not both.")
	case len(t.Jumps) > d.MaxJumps:
		return nil, invalid("Too many jump hosts.")
	case t.dialVariant() != nil && (t.Proxy != nil || len(t.Jumps) > 0):
		return nil, invalid("This connection cannot use a jump host or a SOCKS5 proxy.")
	}
	hops := make([]hop, 0, len(t.Jumps)+1)
	for _, j := range t.Jumps {
		hops = append(hops, hop{Hop: j, role: RoleJump})
	}
	hops = append(hops, hop{Hop: t.Hop, role: RoleTarget})
	for i := range hops {
		h := &hops[i]
		canonical, err := netpolicy.CanonicalHost(h.Host)
		if err != nil {
			return nil, fail(ctx, h.role, false, err)
		}
		h.Host = canonical
		switch {
		case h.Port < 1 || h.Port > 65535:
			return nil, fail(ctx, h.role, false, fault.New(fault.InvalidValue, "Port must be between 1 and 65535."))
		case h.User == "":
			return nil, fail(ctx, h.role, false, fault.New(fault.InvalidValue, "Username is required."))
		case h.Auth.Password == "" && h.Auth.KeyID == "" && (h.role != RoleTarget || t.authVariant() == nil):
			return nil, fail(ctx, h.role, false, fault.New(fault.InvalidValue, "No authentication method provided."))
		}
	}
	for i := range hops {
		h := &hops[i]
		var err error
		switch {
		case t.dialVariant() != nil:
			// The variant reaches the target itself.
		case i > 0:
			h.dest, err = d.Net.JumpDestination(ctx, h.Host, h.Port, i < len(hops)-1)
		case t.Proxy != nil:
			h.dest, err = d.Net.SOCKSDestination(ctx, h.Host, h.Port, t.Proxy.RemoteDNS)
		}
		if err != nil {
			return nil, fail(ctx, h.role, false, err)
		}
	}
	for i := range hops {
		h := &hops[i]
		if h.Auth.KeyID == "" {
			continue
		}
		if d.Keys == nil {
			return nil, invalid("The SSH dialer is not configured.")
		}
		signer, err := d.Keys.Signer(ctx, t.Owner, h.Auth.KeyID)
		if err != nil {
			return nil, fail(ctx, h.role, false, err)
		}
		h.signer = signer
	}
	return hops, nil
}

// routeOf records the pinned peer of the first TCP connection and what
// each relay was asked to reach.
func routeOf(first net.Addr, t Target, hops []hop) Route {
	var r Route
	if first != nil {
		if ap, err := netip.ParseAddrPort(first.String()); err == nil {
			r.Peer = ap.Addr()
		}
	}
	switch {
	case t.Proxy != nil:
		r.Onward = []string{hops[0].dest}
	case len(hops) > 1:
		for _, h := range hops[1:] {
			r.Onward = append(r.Onward, h.dest)
		}
	}
	return r
}

// firstConn opens the TCP connection to the first hop, or to the SOCKS5
// proxy and through it to the first hop.
func (d *Dialer) firstConn(ctx context.Context, t Target, hops []hop) (net.Conn, error) {
	tctx, cancel := context.WithTimeout(ctx, d.HandshakeTimeout)
	defer cancel()
	first := hops[0]
	proxy := t.Proxy
	if dial := t.dialVariant(); dial != nil {
		conn, err := dial(tctx, first.Hop)
		if err != nil {
			return nil, fail(tctx, first.role, false, err)
		}
		return conn, nil
	}
	if proxy == nil {
		dial := d.Net.DialContext
		if len(hops) > 1 {
			dial = d.Net.DialRelay
		}
		conn, err := dial(tctx, netpolicy.RoleSSH, "tcp", joinHostPort(first.Host, first.Port))
		if err != nil {
			return nil, fail(tctx, first.role, false, err)
		}
		return conn, nil
	}
	conn, err := d.Net.DialRelay(tctx, netpolicy.RoleSOCKS, "tcp", joinHostPort(proxy.Host, proxy.Port))
	if err != nil {
		if _, ok := fault.From(err); !ok && tctx.Err() == nil {
			err = socksFail("socks_proxy_unreachable")
		}
		return nil, fail(tctx, RoleSOCKS, false, err)
	}
	if err := socksConnect(tctx, conn, proxy, first.dest, first.Port); err != nil {
		_ = conn.Close()
		return nil, fail(tctx, RoleSOCKS, false, err)
	}
	return conn, nil
}

// channelConn opens the direct-tcpip channel from the previous hop to h.
func (d *Dialer) channelConn(ctx context.Context, via *ssh.Client, h hop) (net.Conn, error) {
	tctx, cancel := context.WithTimeout(ctx, d.HandshakeTimeout)
	defer cancel()
	conn, err := via.DialContext(tctx, "tcp", joinHostPort(h.dest, h.Port))
	if err != nil {
		return nil, fail(tctx, h.role, false, err)
	}
	return conn, nil
}

// OpenShell connects to the target of t and starts an interactive shell
// with a PTY of rows x cols. Closing the shell closes the whole connection.
func (d *Dialer) OpenShell(ctx context.Context, t Target, ix Interaction, rows, cols int) (Shell, error) {
	conn, err := d.Dial(ctx, t, ix)
	if err != nil {
		return nil, err
	}
	shell, err := conn.openShell(ctx, rows, cols)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	shell.closeConn = conn
	return shell, nil
}
