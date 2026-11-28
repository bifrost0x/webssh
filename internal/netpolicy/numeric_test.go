package netpolicy

import (
	"context"
	"errors"
	"net/netip"
	"testing"
)

// The expected values are socket.inet_aton of CPython on glibc, which is
// what getaddrinfo and an OpenSSH or SOCKS relay apply to such a name.
func TestInetAtonMatchesTheCLibrary(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"1681915909", "100.64.0.5"},
		{"0x64400005", "100.64.0.5"},
		{"100.64.5", "100.64.0.5"},
		{"0144.0100.0.5", "100.64.0.5"},
		{"0x", ""},
		{"0", "0.0.0.0"},
		{"00", "0.0.0.0"},
		{"08", ""},
		{"1.2.3.4.5", ""},
		{"4294967295", "255.255.255.255"},
		{"4294967296", ""},
		{"1.16777215", "1.255.255.255"},
		{"1.16777216", ""},
		{"1.0x", ""},
		{"1.2.65535", "1.2.255.255"},
		{"1.2.65536", ""},
		{"0x7f.1", "127.0.0.1"},
		{"1..1", ""},
		{"127.1", "127.0.0.1"},
		{"0377.0377.0377.0377", "255.255.255.255"},
		{"0400.1.1.1", ""},
		{"1-2", ""},
		{"a", ""},
		{"123abc", ""},
		{"example.com", ""},
		{"10", "0.0.0.10"},
		{"1.2.3.4", "1.2.3.4"},
		{"0x100.1.1.1", ""},
		{"00000000000012", "0.0.0.10"},
		{"+1", ""},
		{"0x-1", ""},
	} {
		addr, ok := inetAton(tc.in)
		got := ""
		if ok {
			got = addr.String()
		}
		if got != tc.want {
			t.Errorf("inetAton(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func FuzzInetAton(f *testing.F) {
	for _, s := range []string{"1681915909", "0x64400005", "100.64.5", "0144.0100.0.5", "1.2.3.4"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		addr, ok := inetAton(s)
		if ok && !addr.Is4() {
			t.Fatalf("inetAton(%q) = %v, not IPv4", s, addr)
		}
		if lit, err := netip.ParseAddr(s); err == nil && lit.Is4() && (!ok || addr != lit) {
			t.Fatalf("inetAton(%q) = %v %v, want the dotted literal", s, addr, ok)
		}
	})
}

type nxResolver map[string][]netip.Addr

func (r nxResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if a, ok := r[host]; ok {
		return a, nil
	}
	return nil, errors.New("no such host")
}

func tailnetPolicy(t *testing.T, blockInternal bool) *Policy {
	t.Helper()
	p, err := New(Config{BlockInternal: blockInternal, Resolver: nxResolver{}, Tailnet: Tailnet{
		Interface: "tailscale0", InterfaceConfigured: true,
		Lookup: func(_ context.Context, a netip.Addr) (Route, error) {
			if tailnetV4.Contains(a) {
				return Route{Interface: "tailscale0"}, nil
			}
			return Route{Interface: "eth0"}, nil
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// A relay resolves a numeric IPv4 form with inet_aton, so the tailnet rule
// must refuse it like the dotted address instead of passing the name on.
func TestNumericIPv4FormsDoNotBypassTheTailnetRule(t *testing.T) {
	ctx := t.Context()
	p := tailnetPolicy(t, false)
	for _, host := range []string{"100.64.0.5", "1681915909", "0x64400005", "100.64.5", "0144.0100.0.5"} {
		if d, err := p.JumpDestination(ctx, host, 22, false); !errors.Is(err, ErrTailnetRestricted) {
			t.Errorf("JumpDestination(%q) = %q, %v; want the tailnet refusal", host, d, err)
		}
		if d, err := p.SOCKSDestination(ctx, host, 22, true); !errors.Is(err, ErrTailnetRestricted) {
			t.Errorf("SOCKSDestination(%q) = %q, %v; want the tailnet refusal", host, d, err)
		}
		if !p.OpenRouteRestricted(ctx, netip.MustParseAddr("172.17.0.2"), []string{host}) {
			t.Errorf("OpenRouteRestricted(peer, %q) = false, want true", host)
		}
	}
}

// Outside the tailnet a numeric form reaches the address it stands for,
// as it did through getaddrinfo in the Python release, and a relay gets
// the address, not the name.
func TestNumericIPv4FormsResolveToTheirAddress(t *testing.T) {
	ctx := t.Context()
	p := tailnetPolicy(t, false)
	adm, err := p.Admit(ctx, RoleSSH, "3405803781", 22) // 203.0.113.5
	if err != nil || adm.Addr.Addr() != netip.MustParseAddr("203.0.113.5") || adm.Host != "3405803781" {
		t.Fatalf("Admit = %+v, %v", adm, err)
	}
	if d, err := p.JumpDestination(ctx, "203.0.5", 22, false); err != nil || d != "203.0.0.5" {
		t.Errorf("JumpDestination = %q, %v; want 203.0.0.5", d, err)
	}
	if d, err := p.SOCKSDestination(ctx, "0xcb007105", 22, true); err != nil || d != "203.0.113.5" {
		t.Errorf("SOCKSDestination = %q, %v; want 203.0.113.5", d, err)
	}
	blocking := tailnetPolicy(t, true)
	if _, err := blocking.JumpDestination(ctx, "2130706433", 22, false); err == nil {
		t.Error("JumpDestination(2130706433) with BLOCK_INTERNAL_SSH: want a refusal for 127.0.0.1")
	}
	if _, err := blocking.SOCKSDestination(ctx, "0x7f.1", 22, true); err == nil {
		t.Error("SOCKSDestination(0x7f.1) with BLOCK_INTERNAL_SSH: want a refusal for 127.0.0.1")
	}
}
