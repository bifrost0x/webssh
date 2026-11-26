package main

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/bifrost0x/webssh/internal/audit"
	"github.com/bifrost0x/webssh/internal/config"
	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/hosts"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/ssh/client"
	"github.com/bifrost0x/webssh/internal/ssh/gateway"
	"github.com/bifrost0x/webssh/internal/ssh/tailscale"
	"github.com/bifrost0x/webssh/internal/terminal"
)

// gatewayArea wires the area "gateway" (NW2): the SSH gateway and Tailscale SSH (internal/ssh/gateway, internal/ssh/tailscale).
// NW2 fills in the hooks; no other package edits this file.
func gatewayArea() extension {
	return extension{
		name: "gateway",
		prepare: func(sys *system) error {
			v := newVariantProvider(sys)
			sys.optional.terminalVariants = v
			sys.optional.hostVariants = v
			sys.optional.tailscaleAllowed = v.tailscaleAllowed
			return nil
		},
		wire: func(sys *system) error {
			v, ok := sys.optional.terminalVariants.(*variantProvider)
			if !ok {
				return nil
			}
			sys.realtime.Mount(v.registry.Routes()...)
			return nil
		},
		background: func(_ context.Context, sys *system) {
			warnTailnetGap(sys)
		},
	}
}

var (
	_ terminal.Variants = (*variantProvider)(nil)
	_ hosts.Variants    = (*variantProvider)(nil)
)

// variantProvider prepares gateway and Tailscale SSH connections for the
// terminal and checks the same fields of saved hosts.
type variantProvider struct {
	sys      *system
	registry *gateway.Registry
	policy   *tailscale.Policy
}

func newVariantProvider(sys *system) *variantProvider {
	v := &variantProvider{sys: sys}
	v.registry = &gateway.Registry{Enabled: v.gatewayOn}
	v.policy = tailscale.New(tailscaleConfig(sys.cfg.Network), func(ctx context.Context, host string) ([]netip.Addr, error) {
		return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	}, nil)
	return v
}

func tailscaleConfig(n config.Network) tailscale.Config {
	c := tailscale.Config{Enabled: n.TailscaleSSHEnabled, Interface: n.TailscaleInterface,
		AllowedWebSSHUsers: n.Tailscale.AllowedWebSSHUsers, AllowedRemoteUsers: n.Tailscale.AllowedRemoteUsers}
	for _, t := range n.Tailscale.AllowedTargets {
		c.AllowedTargets = append(c.AllowedTargets, tailscale.Target{Host: t.Host, Port: t.Port})
	}
	return c
}

// gatewayOn reads the administrator switch ssh_gateway_enabled; a failure
// to read it counts as off (fail closed).
func (v *variantProvider) gatewayOn(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	app, err := v.sys.settings.App(ctx)
	if err != nil {
		v.sys.log.Warn("gateway setting unreadable; the gateway stays off", "err", err)
		return false
	}
	return app.SSHGatewayEnabled
}

var errGatewayClient = fault.New(fault.InvalidRequest, "Gateway connections require an updated interactive client")

// Prepare implements terminal.Variants.
func (v *variantProvider) Prepare(ctx context.Context, a terminal.VariantAttempt) (client.Target, context.Context, func(), error) {
	t := a.Target
	if t.Display.Tailscale {
		auth, err := v.policy.Authorize(ctx, tsUser(a.User), t.Hop.Host, t.Hop.Port, t.Hop.User)
		v.auditTailscale(a.User, t, err)
		if err != nil {
			return client.Target{}, nil, nil, err
		}
		t.Hop.Host, t.Hop.User = auth.Host(), auth.RemoteUser()
		t.Variant = auth.Variant()
		return t, ctx, func() {}, nil
	}
	if !a.Interactive {
		return client.Target{}, nil, nil, errGatewayClient
	}
	if _, _, err := gateway.ParseSelector(t.Hop.User); err != nil {
		return client.Target{}, nil, nil, err
	}
	attempt, actx, end, err := v.registry.Begin(ctx, gateway.Owner{Peer: a.Peer.ID(), UserID: a.User.UserID}, a.RequestID, a.Peer, true)
	if err != nil {
		return client.Target{}, nil, nil, err
	}
	t.Variant = attempt.Variant(true)
	return t, actx, end, nil
}

// Interact implements terminal.Variants for an ordinary connection whose
// page answers prompts: an attempt without the gateway switch carries the
// keyboard-interactive rounds to the page (ssh_interaction).
func (v *variantProvider) Interact(ctx context.Context, a terminal.VariantAttempt) (client.Challenger, context.Context, func(), error) {
	attempt, actx, end, err := v.registry.Begin(ctx, gateway.Owner{Peer: a.Peer.ID(), UserID: a.User.UserID}, a.RequestID, a.Peer, false)
	if err != nil {
		return nil, nil, nil, err
	}
	return attempt.Challenger(), actx, end, nil
}

func tsUser(p principal.Principal) tailscale.User {
	return tailscale.User{ID: p.UserID, Username: p.Username, IsAdmin: p.IsAdmin}
}

// auditTailscale records every use of the shared node identity, as
// log_tailscale_ssh_usage did.
func (v *variantProvider) auditTailscale(p principal.Principal, t client.Target, err error) {
	if v.sys.audit == nil {
		return
	}
	status := "TAILSCALE_SSH_AUTHORIZED"
	fields := []audit.Field{audit.F("user", p.Username), audit.F("target", netJoin(t.Hop.Host, t.Hop.Port)),
		audit.F("remote_user", t.Hop.User), audit.F("identity", "shared-node")}
	if err != nil {
		status = "TAILSCALE_SSH_DENIED"
		_, _, msg := fault.Status(err)
		fields = append(fields, audit.F("error", msg))
	}
	v.sys.audit.Event(audit.Info, status, fields...)
}

func netJoin(host string, port int) string {
	return net.JoinHostPort(host, strconv.Itoa(port))
}

// GatewayEnabled implements hosts.Variants.
func (v *variantProvider) GatewayEnabled(ctx context.Context) error {
	if !v.gatewayOn(ctx) {
		return gateway.ErrDisabled
	}
	return nil
}

// GatewaySelector implements hosts.Variants.
func (v *variantProvider) GatewaySelector(username string) error {
	_, _, err := gateway.ParseSelector(username)
	return err
}

// TailscaleAccess implements hosts.Variants for the principal of ctx.
func (v *variantProvider) TailscaleAccess(ctx context.Context, host string, port int, remoteUser string) error {
	p, ok := principal.From(ctx)
	if !ok {
		return tailscale.ErrNotEnabled
	}
	return v.policy.Check(tsUser(p), host, port, remoteUser)
}

// tailscaleAllowed is tailscale_ssh_allowed of the pages.
func (v *variantProvider) tailscaleAllowed(p principal.Principal) bool {
	return v.policy.UserMayUse(tsUser(p))
}

// warnTailnetGap tells the administrator at every start that an upgraded
// installation still lets ordinary SSH reach tailnet nodes (D-28 under
// D-01), as the Python release warned.
func warnTailnetGap(sys *system) {
	if sys.policy == nil || !sys.policy.TailnetLegacyGap() {
		return
	}
	const msg = "Tailscale SSH is disabled but the Tailscale interface exists; ordinary SSH to tailnet nodes is not blocked " +
		"(setting netpolicy.tailnet_follows_switch carried over from the previous release), see docs/tailscale-ssh.md"
	sys.log.Warn(msg, "interface", sys.cfg.Network.TailscaleInterface)
	if sys.audit != nil {
		sys.audit.Event(audit.Warning, "TAILNET_ROUTE_RESTRICTION_FOLLOWS_SWITCH",
			audit.F("message", msg), audit.F("interface", sys.cfg.Network.TailscaleInterface))
	}
}
