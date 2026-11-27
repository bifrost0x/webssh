//go:build linux

package client_test

import (
	"context"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/netpolicy"
	"github.com/bifrost0x/webssh/internal/ssh/client"
)

// labKeys trusts the host keys of the lab targets by fingerprint.
type labKeys []string

func (k labKeys) Known(_ context.Context, _ int64, _ string, _ int, key ssh.PublicKey) (bool, error) {
	if slices.Contains(k, ssh.FingerprintSHA256(key)) {
		return true, nil
	}
	return false, fault.New(fault.HostKeyChanged, "")
}
func (labKeys) Record(context.Context, int64, string, int, ssh.PublicKey) error { return nil }
func (labKeys) Preferred(_ context.Context, _ int64, _ string, _ int, a []string) ([]string, error) {
	return a, nil
}

// TestLabTailnetBlockOnOpenConnections runs inside lab-ts-node, the
// Tailscale stand-in of the test lab, with the real kernel route lookup:
// an ordinary connection opened to the tailnet node while the block is
// lifted is refused by OpenRouteRestricted once the block is turned on,
// and a connection to ssh-modern on the LAN stays allowed. Run it with
// WEBSSH_NETNS=lab, WEBSSH_TS_FINGERPRINTS, WEBSSH_LAB_SSH_MODERN
// (address:port), WEBSSH_MODERN_FINGERPRINTS and WEBSSH_PWUSER_FILE.
func TestLabTailnetBlockOnOpenConnections(t *testing.T) {
	if os.Getenv("WEBSSH_NETNS") != "lab" {
		t.Skip("run inside lab-ts-node (WEBSSH_NETNS=lab)")
	}
	password, err := os.ReadFile(os.Getenv("WEBSSH_PWUSER_FILE"))
	if err != nil {
		t.Fatal(err)
	}
	var restrict atomic.Bool
	policy, err := netpolicy.New(netpolicy.Config{Tailnet: netpolicy.Tailnet{
		Restricted: restrict.Load, Interface: "tailscale0",
	}})
	if err != nil {
		t.Fatal(err)
	}
	keys := labKeys(slices.Concat(strings.Split(os.Getenv("WEBSSH_TS_FINGERPRINTS"), ","),
		strings.Split(os.Getenv("WEBSSH_MODERN_FINGERPRINTS"), ",")))
	d := &client.Dialer{Net: policy, HostKeys: keys, Keepalive: -1}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	restrict.Store(true)
	if _, err := policy.Admit(ctx, netpolicy.RoleSSH, "100.100.100.10", 22); err == nil {
		t.Fatal("a new connection to the node passes the block")
	}
	restrict.Store(false)
	node, err := d.Dial(ctx, client.Target{Owner: 1, Hop: client.Hop{Host: "100.100.100.10", Port: 22, User: "tsuser",
		Auth: client.Auth{Password: "unused"}}}, nil)
	if err != nil {
		t.Fatalf("ordinary connection to the node with the block lifted: %v", err)
	}
	defer func() { _ = node.Close() }()
	host, port, _ := strings.Cut(os.Getenv("WEBSSH_LAB_SSH_MODERN"), ":")
	if port != "22" {
		t.Fatalf("WEBSSH_LAB_SSH_MODERN %q", os.Getenv("WEBSSH_LAB_SSH_MODERN"))
	}
	lan, err := d.Dial(ctx, client.Target{Owner: 1, Hop: client.Hop{Host: host, Port: 22, User: "pwuser",
		Auth: client.Auth{Password: strings.TrimSpace(string(password))}}}, nil)
	if err != nil {
		t.Fatalf("connection to ssh-modern: %v", err)
	}
	defer func() { _ = lan.Close() }()

	nodeRoute, ok1 := node.Route()
	lanRoute, ok2 := lan.Route()
	if !ok1 || !ok2 || nodeRoute.Peer.String() != "100.100.100.10" || lanRoute.Peer.String() != host {
		t.Fatalf("routes %+v %+v", nodeRoute, lanRoute)
	}
	if policy.OpenRouteRestricted(ctx, nodeRoute.Peer, nodeRoute.Onward) {
		t.Fatal("restricted with the block lifted")
	}
	restrict.Store(true)
	if !policy.OpenRouteRestricted(ctx, nodeRoute.Peer, nodeRoute.Onward) {
		t.Fatal("the open connection to the tailnet node passes the block")
	}
	if policy.OpenRouteRestricted(ctx, lanRoute.Peer, lanRoute.Onward) {
		t.Fatal("the connection to ssh-modern on the LAN is refused")
	}
	// A relay asked to reach the node, a relay on this host (tailscaled's
	// SOCKS5 proxy) and a LAN jump host to a LAN target.
	loopback := netip.MustParseAddr("127.0.0.1")
	switch {
	case !policy.OpenRouteRestricted(ctx, lanRoute.Peer, []string{"100.100.100.10"}):
		t.Fatal("a jump host to the node passes the block")
	case !policy.OpenRouteRestricted(ctx, loopback, []string{host}):
		t.Fatal("a relay on this host passes the block")
	case policy.OpenRouteRestricted(ctx, lanRoute.Peer, []string{host}):
		t.Fatal("a LAN jump chain is refused")
	}
}
