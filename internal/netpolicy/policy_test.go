package netpolicy

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/bifrost0x/webssh/internal/fault"
)

type countingResolver struct {
	names map[string][]string
	calls atomic.Int32
}

func (c *countingResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	c.calls.Add(1)
	return mapResolver(c.names).LookupNetIP(ctx, network, host)
}

type recordingDial struct{ addrs []string }

func (r *recordingDial) dial(_ context.Context, _, addr string) (net.Conn, error) {
	r.addrs = append(r.addrs, addr)
	return nil, errDialed
}

func newTestPolicy(t *testing.T, cfg Config) (*Policy, *recordingDial, *countingResolver) {
	t.Helper()
	rec := &recordingDial{}
	res := &countingResolver{names: map[string][]string{
		"lan.example":    {"192.168.1.5"},
		"mixed.example":  {"127.0.0.1", "192.168.1.5", "8.8.8.8"},
		"public.example": {"8.8.8.8"},
		"node.example":   {"100.100.100.10"},
	}}
	cfg.Dial, cfg.Resolver = rec.dial, res
	cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	if cfg.Tailnet.InterfacePresent == nil {
		cfg.Tailnet.InterfacePresent = func(string) bool { return false }
	}
	cfg.Tailnet.Lookup = labRoutes.lookup
	if cfg.Tailnet.Interface == "" {
		cfg.Tailnet.Interface = "tailscale0"
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return p, rec, res
}

var roles = []Role{RoleSSH, RoleSMB, RoleSOCKS, RoleProbe}

// ADR 0010: without BLOCK_INTERNAL_SSH nothing is restricted by class, for
// every role: remote hosts, the LAN, the WebSSH host itself and link-local
// addresses are all reachable.
func TestDefaultHasNoTargetRestriction(t *testing.T) {
	p, _, _ := newTestPolicy(t, Config{})
	for _, role := range roles {
		for _, host := range []string{"127.0.0.1", "::1", "169.254.169.254", "fe80::1%eth0", "10.0.0.1", "100.64.0.1", "0.0.0.0", "224.0.0.1", "8.8.8.8", "lan.example"} {
			if _, err := p.Admit(t.Context(), role, host, 22); err != nil {
				t.Errorf("%s %s: %v", role, host, err)
			}
		}
	}
}

// BLOCK_INTERNAL_SSH=true is one rule set for every role; the allowance
// re-admits private networks but never loopback or link-local.
func TestBlockInternalAppliesToEveryRole(t *testing.T) {
	p, _, _ := newTestPolicy(t, Config{BlockInternal: true, AllowedInternal: []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")}})
	cases := map[string]bool{
		"127.0.0.1": false, "::1": false, "169.254.169.254": false, "0.0.0.0": false,
		"10.0.0.1": false, "100.64.0.1": false, "224.0.0.1": false, "::ffff:192.168.1.5": false,
		"fc00::1": false, "192.168.1.5": true, "lan.example": true, "8.8.8.8": true,
	}
	for _, role := range roles {
		for host, allowed := range cases {
			_, err := p.Admit(t.Context(), role, host, 22)
			if allowed != (err == nil) {
				t.Errorf("%s %s: allowed=%v, err=%v", role, host, allowed, err)
			}
			if err != nil && !fault.Is(err, fault.TargetBlocked) {
				t.Errorf("%s %s: code %s", role, host, fault.CodeOf(err))
			}
		}
	}
}

// The name is resolved once and the connection goes to the admitted
// address, never to a refused earlier candidate.
func TestDialUsesTheAdmittedAddress(t *testing.T) {
	p, rec, res := newTestPolicy(t, Config{BlockInternal: true, AllowedInternal: []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")}})
	if _, err := p.DialContext(t.Context(), RoleSSH, "tcp", "mixed.example:2222"); !errors.Is(err, errDialed) {
		t.Fatal(err)
	}
	if len(rec.addrs) != 1 || rec.addrs[0] != "192.168.1.5:2222" || res.calls.Load() != 1 {
		t.Fatalf("dialed %v after %d lookups", rec.addrs, res.calls.Load())
	}
	adm, err := p.Admit(t.Context(), RoleSSH, "lan.example", 22)
	if err != nil || !adm.ViaAllowance || adm.Host != "lan.example" {
		t.Fatalf("admitted %+v, %v", adm, err)
	}
}

func TestDialRefusesMalformedRequests(t *testing.T) {
	p, rec, _ := newTestPolicy(t, Config{})
	for _, c := range []struct{ network, addr string }{
		{"udp", "8.8.8.8:22"}, {"tcp", "8.8.8.8"}, {"tcp", "8.8.8.8:0"}, {"tcp", "8.8.8.8:70000"},
		{"tcp", "8.8.8.8:x"}, {"tcp", "bad_name:22"}, {"tcp", ":22"},
	} {
		if _, err := p.DialContext(t.Context(), RoleSSH, c.network, c.addr); err == nil || errors.Is(err, errDialed) {
			t.Errorf("%s %s: %v", c.network, c.addr, err)
		}
	}
	if len(rec.addrs) != 0 {
		t.Fatalf("dialed %v", rec.addrs)
	}
}

func TestTailnetRuleInDialer(t *testing.T) {
	p, rec, _ := newTestPolicy(t, Config{Tailnet: Tailnet{InterfacePresent: func(string) bool { return true }}})
	for _, addr := range []string{"100.100.100.10:22", "[::ffff:100.100.100.10]:22", "node.example:22", "100.99.0.1:22"} {
		_, err := p.DialContext(t.Context(), RoleSSH, "tcp", addr)
		if !errors.Is(err, ErrTailnetRestricted) || !fault.Is(err, fault.TailnetRouteRestricted) {
			t.Errorf("%s: %v", addr, err)
		}
	}
	// A loopback target is fine, a loopback relay is not.
	if _, err := p.DialContext(t.Context(), RoleSSH, "tcp", "127.0.0.1:22"); !errors.Is(err, errDialed) {
		t.Errorf("loopback target: %v", err)
	}
	for _, dial := range []func() error{
		func() error { _, err := p.DialRelay(t.Context(), RoleSSH, "tcp", "127.0.0.1:22"); return err },
		func() error { _, err := p.DialContext(t.Context(), RoleSOCKS, "tcp", "127.0.0.1:1080"); return err },
	} {
		if err := dial(); !errors.Is(err, ErrTailnetRestricted) {
			t.Errorf("loopback relay: %v", err)
		}
	}
	if _, err := p.JumpDestination(t.Context(), "box.tail1234.ts.net", 22, false); !errors.Is(err, ErrTailnetRestricted) {
		t.Errorf("MagicDNS behind a jump host: %v", err)
	}
	if _, err := p.SOCKSDestination(t.Context(), "box.tail1234.ts.net", 22, true); !errors.Is(err, ErrTailnetRestricted) {
		t.Errorf("MagicDNS behind SOCKS5: %v", err)
	}
	if len(rec.addrs) != 1 {
		t.Fatalf("dialed %v", rec.addrs)
	}
}

func TestDestinations(t *testing.T) {
	p, _, _ := newTestPolicy(t, Config{BlockInternal: true, JumpRemoteDNS: []string{"only-remote.corp"}})
	if got, err := p.JumpDestination(t.Context(), "Public.Example.", 22, false); err != nil || got != "8.8.8.8" {
		t.Errorf("resolvable name is pinned: %q, %v", got, err)
	}
	if got, err := p.JumpDestination(t.Context(), "only-remote.corp", 22, false); err != nil || got != "only-remote.corp" {
		t.Errorf("allowlisted name goes to the bastion: %q, %v", got, err)
	}
	if _, err := p.JumpDestination(t.Context(), "elsewhere.corp", 22, false); !fault.Is(err, fault.TargetBlocked) {
		t.Errorf("name outside the allowlist: %v", err)
	}
	if _, err := p.SOCKSDestination(t.Context(), "fe80::1%eth0", 22, true); !fault.Is(err, fault.InvalidValue) {
		t.Errorf("scoped address through SOCKS5: %v", err)
	}
	if _, err := p.SOCKSDestination(t.Context(), "lan.example", 0, true); !fault.Is(err, fault.InvalidValue) {
		t.Errorf("port 0: %v", err)
	}
}

func TestResolveHonoursContext(t *testing.T) {
	p, _, _ := newTestPolicy(t, Config{})
	p.cfg.Resolver = cancelledResolver{}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := p.Admit(ctx, RoleSSH, "lan.example", 22); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
}

type cancelledResolver struct{}

func (cancelledResolver) LookupNetIP(ctx context.Context, _, _ string) ([]netip.Addr, error) {
	return nil, ctx.Err()
}

func TestNewValidatesConfiguration(t *testing.T) {
	for name, cfg := range map[string]Config{
		"public network":   {AllowedInternal: []netip.Prefix{netip.MustParsePrefix("8.8.8.0/24")}},
		"loopback":         {AllowedInternal: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}},
		"host bits":        {AllowedInternal: []netip.Prefix{netip.MustParsePrefix("10.1.2.3/8")}},
		"wider than 10/8":  {AllowedInternal: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/7")}},
		"IP in allowlist":  {JumpRemoteDNS: []string{"10.0.0.1"}},
		"not canonical":    {SOCKSRemoteDNS: []string{"Upper.Example"}},
		"invalid hostname": {SOCKSRemoteDNS: []string{"bad_name"}},
	} {
		if _, err := New(cfg); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := New(Config{AllowedInternal: []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("fd00::/8")}}); err != nil {
		t.Fatal(err)
	}
}

func FuzzCanonicalHost(f *testing.F) {
	for _, s := range []string{"Example.COM.", "[::1]", "fe80::1%eth0", "::ffff:1.2.3.4", "a..b", " x ", "bücher.de", "1.2.3.4"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		out, err := CanonicalHost(in)
		if err != nil || strings.Contains(out, "%") {
			// A scope is taken verbatim, as Python does, so it may end in
			// characters a second pass strips.
			return
		}
		again, err := CanonicalHost(out)
		if err != nil || again != out {
			t.Fatalf("not idempotent: %q -> %q -> %q, %v", in, out, again, err)
		}
	})
}

// Every jump host after the first is a relay as well: its address must
// pass the relay rule, and a name it would resolve itself is refused while
// the tailnet rule applies.
func TestJumpRelayDestination(t *testing.T) {
	p, _, _ := newTestPolicy(t, Config{Tailnet: Tailnet{InterfacePresent: func(string) bool { return true }}})
	for _, host := range []string{"127.0.0.1", "only-remote.corp"} {
		if _, err := p.JumpDestination(t.Context(), host, 22, true); !errors.Is(err, ErrTailnetRestricted) {
			t.Errorf("relay %s: %v", host, err)
		}
		if _, err := p.JumpDestination(t.Context(), host, 22, false); err != nil {
			t.Errorf("target %s: %v", host, err)
		}
	}
	if got, err := p.JumpDestination(t.Context(), "fe80::1%eth0", 22, false); err != nil || got != "fe80::1" {
		t.Errorf("zone must not be sent to a relay: %q %v", got, err)
	}
}
