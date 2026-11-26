package netpolicy

import (
	"context"
	json "encoding/json/v2"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"

	"github.com/bifrost0x/webssh/internal/fault"
)

// testdata/python_vectors.json is produced by testdata/python_vectors.py
// from the unchanged Python modules; see the script for the command.

type pyOutcome struct {
	OK    bool   `json:"ok"`
	Error string `json:"error"`
	IP    string `json:"ip"`
	Via   bool   `json:"via"`
	Name  string `json:"name"`
}

type pyMode struct {
	Block    bool     `json:"block"`
	Allow    []string `json:"allow"`
	Tailnet  bool     `json:"tailnet"`
	JumpDNS  []string `json:"jump_dns"`
	SOCKSDNS []string `json:"socks_dns"`
}

type pyVectors struct {
	Routes   map[string]string   `json:"routes"`
	Names    map[string][]string `json:"names"`
	Classify []struct {
		Addr        string `json:"addr"`
		Internal    bool   `json:"internal"`
		Allowlisted bool   `json:"allowlisted"`
		Node        bool   `json:"node"`
	} `json:"classify"`
	Canonical []struct {
		In  string `json:"in"`
		OK  bool   `json:"ok"`
		Out string `json:"out"`
	} `json:"canonical"`
	Cases []struct {
		Mode       pyMode    `json:"mode"`
		Host       string    `json:"host"`
		Target     pyOutcome `json:"target"`
		Relay      pyOutcome `json:"relay"`
		Jump       pyOutcome `json:"jump"`
		SOCKSTrue  pyOutcome `json:"socks_true"`
		SOCKSFalse pyOutcome `json:"socks_false"`
	} `json:"cases"`
}

func loadVectors(t *testing.T) pyVectors {
	t.Helper()
	raw, err := os.ReadFile("testdata/python_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v pyVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Classify) < 1000 || len(v.Cases) < 100 {
		t.Fatalf("vector file is incomplete: %d addresses, %d cases", len(v.Classify), len(v.Cases))
	}
	return v
}

func TestClassificationMatchesPython(t *testing.T) {
	v := loadVectors(t)
	allow := []netip.Prefix{
		netip.MustParsePrefix("10.20.0.0/16"), netip.MustParsePrefix("100.64.0.0/10"),
		netip.MustParsePrefix("fd00::/8"), netip.MustParsePrefix("192.168.0.0/16"),
	}
	for _, c := range v.Classify {
		addr := netip.MustParseAddr(c.Addr)
		if got := Internal(addr); got != c.Internal {
			t.Errorf("%s: internal %v, Python %v (class %s)", c.Addr, got, c.Internal, Classify(addr))
		}
		if got := allowlisted(addr, allow); got != c.Allowlisted {
			t.Errorf("%s: allowlisted %v, Python %v", c.Addr, got, c.Allowlisted)
		}
		if _, got := NodeAddress(addr); got != c.Node {
			t.Errorf("%s: node %v, Python %v", c.Addr, got, c.Node)
		}
	}
}

func TestCanonicalHostMatchesPython(t *testing.T) {
	for _, c := range loadVectors(t).Canonical {
		got, err := CanonicalHost(c.In)
		switch {
		case c.OK && (err != nil || got != c.Out):
			t.Errorf("%q: Go %q, %v; Python %q", c.In, got, err, c.Out)
		case !c.OK && err == nil:
			t.Errorf("%q: Go accepts %q, Python refuses", c.In, got)
		}
	}
}

type mapResolver map[string][]string

func (m mapResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	ips, ok := m[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	out := make([]netip.Addr, len(ips))
	for i, s := range ips {
		out[i] = netip.MustParseAddr(s)
	}
	return out, nil
}

func routeTable(routes map[string]string) RouteLookup {
	return func(_ context.Context, addr netip.Addr) (Route, error) {
		name, ok := routes[addr.String()]
		if !ok {
			return Route{}, errors.New("no route")
		}
		return Route{Interface: name, Local: name == "lo"}, nil
	}
}

var errDialed = errors.New("dialed")

func pythonModePolicy(t *testing.T, v pyVectors, m pyMode, dialed *string) *Policy {
	t.Helper()
	cfg := Config{
		BlockInternal:  m.Block,
		JumpRemoteDNS:  m.JumpDNS,
		SOCKSRemoteDNS: m.SOCKSDNS,
		Tailnet: Tailnet{
			Interface: "tailscale0", FeatureEnabled: m.Tailnet,
			Lookup: routeTable(v.Routes), InterfacePresent: func(string) bool { return false },
		},
		Resolver: mapResolver(v.Names),
		Dial: func(_ context.Context, _, addr string) (net.Conn, error) {
			*dialed = addr
			return nil, errDialed
		},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	for _, a := range m.Allow {
		cfg.AllowedInternal = append(cfg.AllowedInternal, netip.MustParsePrefix(a))
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func errorKind(err error) string {
	switch {
	case errors.Is(err, ErrTailnetRestricted):
		return "tailnet"
	case fault.Is(err, fault.Unreachable):
		return "unresolved"
	case fault.Is(err, fault.TargetBlocked):
		return "blocked"
	case fault.Is(err, fault.InvalidValue):
		return "invalid"
	}
	return "other: " + err.Error()
}

func compare(t *testing.T, what string, want pyOutcome, got string, err error) {
	t.Helper()
	switch {
	case !want.OK && err == nil:
		t.Errorf("%s: Go allows %q, Python refuses (%s)", what, got, want.Error)
	case !want.OK && errorKind(err) != want.Error:
		t.Errorf("%s: Go refuses as %s, Python as %s", what, errorKind(err), want.Error)
	case want.OK && err != nil:
		t.Errorf("%s: Go refuses (%s), Python allows %+v", what, errorKind(err), want)
	case want.OK && want.IP+want.Name != "" && got != want.IP+want.Name:
		t.Errorf("%s: Go %q, Python %q", what, got, want.IP+want.Name)
	}
}

// TestPolicyMatchesPython replays every decision of the Python policy for
// targets, relays, jump-host destinations and SOCKS5 destinations.
func TestPolicyMatchesPython(t *testing.T) {
	v := loadVectors(t)
	ctx := t.Context()
	for _, c := range v.Cases {
		var dialed string
		p := pythonModePolicy(t, v, c.Mode, &dialed)
		label := func(kind string) string { return kind + " " + c.Host + " " + modeName(c.Mode) }

		adm, err := p.Admit(ctx, RoleSSH, c.Host, 22)
		got := ""
		if err == nil {
			got = adm.Addr.Addr().String()
			if adm.ViaAllowance != c.Target.Via {
				t.Errorf("%s: via allowance %v, Python %v", label("target"), adm.ViaAllowance, c.Target.Via)
			}
		}
		compare(t, label("target"), c.Target, got, err)

		_, err = p.DialRelay(ctx, RoleSSH, "tcp", net.JoinHostPort(c.Host, "22"))
		if errors.Is(err, errDialed) {
			err = nil
			if c.Target.OK && dialed != netip.AddrPortFrom(netip.MustParseAddr(c.Target.IP), 22).String() {
				t.Errorf("%s: dialed %s, admitted %s", label("relay"), dialed, c.Target.IP)
			}
		}
		compare(t, label("relay"), c.Relay, "", err)

		got, err = p.JumpDestination(ctx, c.Host, 22, false)
		jump := c.Jump
		// Deliberate: the zone of a link-local address is not sent to a
		// jump host (Python sent "fe80::1%eth0").
		if i := strings.IndexByte(jump.IP, '%'); i >= 0 {
			jump.IP = jump.IP[:i]
		}
		compare(t, label("jump"), jump, got, err)
		got, err = p.SOCKSDestination(ctx, c.Host, 22, true)
		compare(t, label("socks remote dns"), c.SOCKSTrue, got, err)
		got, err = p.SOCKSDestination(ctx, c.Host, 22, false)
		compare(t, label("socks local dns"), c.SOCKSFalse, got, err)
	}
}

func modeName(m pyMode) string {
	s := "[block=false"
	if m.Block {
		s = "[block=true"
	}
	if m.Tailnet {
		s += " tailnet"
	}
	return s + "]"
}
