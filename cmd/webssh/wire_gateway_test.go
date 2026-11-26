package main

import (
	"context"
	"encoding/json/jsontext"
	"net/netip"
	"testing"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/netpolicy"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/principal/principaltest"
	"github.com/bifrost0x/webssh/internal/realtime/protocol/protocoltest"
	"github.com/bifrost0x/webssh/internal/settings"
	"github.com/bifrost0x/webssh/internal/ssh/client"
	"github.com/bifrost0x/webssh/internal/ssh/tailscale"
	"github.com/bifrost0x/webssh/internal/store"
	"github.com/bifrost0x/webssh/internal/terminal"
)

func gatewaySystem(t *testing.T) (*system, *variantProvider) {
	t.Helper()
	sys, _ := openTestSystem(t, map[string]string{
		"TAILSCALE_SSH_ENABLED": "true", "TAILSCALE_SSH_ALLOWED_TARGETS": "node.ts.example,100.100.100.10:2222",
		"TAILSCALE_SSH_ALLOWED_WEBSSH_USERS": "alice", "TAILSCALE_SSH_ALLOWED_REMOTE_USERS": "tsuser",
	})
	v, ok := sys.optional.terminalVariants.(*variantProvider)
	if !ok || sys.optional.hostVariants == nil || sys.optional.tailscaleAllowed == nil {
		t.Fatal("the gateway area is not wired")
	}
	return sys, v
}

func setGateway(t *testing.T, sys *system, on bool) {
	t.Helper()
	doc := `{"schema_version":2,"ssh_gateway_enabled":false}`
	if on {
		doc = `{"schema_version":2,"ssh_gateway_enabled":true}`
	}
	if err := sys.db.Write(t.Context(), func(tx *store.Tx) error {
		_, err := settings.ImportApp(t.Context(), tx, jsontext.Value(doc), 1)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestGatewayVariantNeedsTheSwitchAndAnInteractiveClient(t *testing.T) {
	sys, v := gatewaySystem(t)
	alice := principaltest.User(5)
	peer := protocoltest.NewPeer(t, alice)
	attempt := terminal.VariantAttempt{Peer: peer, User: alice, RequestID: "gw-1", Interactive: true,
		Target: client.Target{Owner: 5, Hop: client.Hop{Host: "gw.example", Port: 2222, User: "alice:prod"}}}
	if _, _, _, err := v.Prepare(t.Context(), attempt); fault.CodeOf(err) != fault.Forbidden {
		t.Fatalf("switch off: %v", err)
	}
	setGateway(t, sys, true)
	plain := attempt
	plain.Interactive = false
	if _, _, _, err := v.Prepare(t.Context(), plain); fault.CodeOf(err) != fault.InvalidRequest {
		t.Fatalf("client without prompts: %v", err)
	}
	bad := attempt
	bad.Target.Hop.User = "ticket-x:prod"
	if _, _, _, err := v.Prepare(t.Context(), bad); fault.CodeOf(err) != fault.InvalidValue {
		t.Fatalf("ticket selector: %v", err)
	}
	got, ctx, end, err := v.Prepare(t.Context(), attempt)
	if err != nil {
		t.Fatal(err)
	}
	if got.Variant == nil || got.Variant.Auth == nil || got.Variant.Ready == nil || got.Variant.Dial != nil {
		t.Fatalf("variant %+v", got.Variant)
	}
	if v.registry.Pending() != 1 {
		t.Fatal("attempt not registered")
	}
	if _, _, _, err := v.Prepare(t.Context(), attempt); fault.CodeOf(err) != fault.Busy {
		t.Fatalf("second attempt with the same request id: %v", err)
	}
	end()
	if v.registry.Pending() != 0 || ctx.Err() == nil {
		t.Fatal("end left the attempt behind")
	}
	if err := v.GatewayEnabled(t.Context()); err != nil {
		t.Fatalf("saved hosts while on: %v", err)
	}
	setGateway(t, sys, false)
	if err := v.GatewayEnabled(t.Context()); fault.CodeOf(err) != fault.Forbidden {
		t.Fatalf("saved hosts while off: %v", err)
	}
}

func TestTailscaleVariantFollowsThePolicy(t *testing.T) {
	_, v := gatewaySystem(t)
	alice, bob := principaltest.User(5), principaltest.User(6)
	alice.Username, bob.Username = "alice", "bob"
	tsTarget := func(p principal.Principal, host string, port int, remote string) terminal.VariantAttempt {
		return terminal.VariantAttempt{Peer: protocoltest.NewPeer(t, p), User: p, RequestID: "ts",
			Target: client.Target{Owner: p.UserID, Hop: client.Hop{Host: host, Port: port, User: remote}, Display: client.Display{Tailscale: true}}}
	}
	if _, _, _, err := v.Prepare(t.Context(), tsTarget(bob, "node.ts.example", 22, "tsuser")); fault.CodeOf(err) != fault.Forbidden {
		t.Fatalf("unlisted user: %v", err)
	}
	if _, _, _, err := v.Prepare(t.Context(), tsTarget(alice, "node.ts.example", 22, "root")); fault.CodeOf(err) != fault.Forbidden {
		t.Fatalf("unlisted remote user: %v", err)
	}
	// The host has no route over tailscale0: the policy fails closed.
	if _, _, _, err := v.Prepare(t.Context(), tsTarget(alice, "100.100.100.10", 2222, "tsuser")); fault.CodeOf(err) != fault.Forbidden {
		t.Fatalf("no tailnet route: %v", err)
	}
	v.policy = tailscale.New(tailscaleConfig(v.sys.cfg.Network), nil,
		func(context.Context, netip.Addr) (netpolicy.Route, error) {
			return netpolicy.Route{Interface: "tailscale0", Table: 52}, nil
		})
	got, _, end, err := v.Prepare(t.Context(), tsTarget(alice, "100.100.100.10", 2222, " tsuser "))
	if err != nil {
		t.Fatal(err)
	}
	end()
	if got.Variant == nil || got.Variant.Dial == nil || got.Variant.Ready != nil || got.Hop.User != "tsuser" {
		t.Fatalf("tailscale target %+v", got)
	}
	ctx := principal.With(t.Context(), alice)
	if err := v.TailscaleAccess(ctx, "100.100.100.10", 2222, "tsuser"); err != nil {
		t.Fatalf("saved host check: %v", err)
	}
	if err := v.TailscaleAccess(t.Context(), "100.100.100.10", 2222, "tsuser"); fault.CodeOf(err) != fault.Forbidden {
		t.Fatalf("saved host check without a principal: %v", err)
	}
	if !v.tailscaleAllowed(alice) || v.tailscaleAllowed(bob) {
		t.Fatal("tailscale_ssh_allowed of the pages")
	}
}
