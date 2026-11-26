package tailscale

import (
	"context"
	json "encoding/json/v2"
	"errors"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/netpolicy"
)

// testdata/python_vectors.json is produced by testdata/python_vectors.py
// from the unchanged Python modules; see the script for the command.
type pyVectors struct {
	Routes  map[string]string   `json:"routes"`
	Names   map[string][]string `json:"names"`
	Users   []pyUser            `json:"users"`
	Configs []struct {
		Enabled   bool     `json:"enabled"`
		Interface string   `json:"interface"`
		Users     []string `json:"users"`
		Remote    []string `json:"remote"`
		Targets   [][2]any `json:"targets"`
	} `json:"configs"`
	Cases []struct {
		Config    int             `json:"config"`
		User      int64           `json:"user"`
		Host      string          `json:"host"`
		Port      int             `json:"port"`
		Remote    string          `json:"remote"`
		Check     *string         `json:"check"`
		Authorize *string         `json:"authorize"`
		IP        *string         `json:"ip"`
		Matches   map[string]bool `json:"matches"`
	} `json:"cases"`
}

type pyUser struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
	IsAdmin  bool   `json:"is_admin"`
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
	if len(v.Cases) < 3000 || len(v.Configs) < 5 {
		t.Fatalf("vector file is incomplete: %d cases", len(v.Cases))
	}
	return v
}

func tableLookup(routes map[string]string) netpolicy.RouteLookup {
	return func(_ context.Context, addr netip.Addr) (netpolicy.Route, error) {
		name, ok := routes[addr.String()]
		if !ok {
			return netpolicy.Route{}, errors.New("no route")
		}
		return netpolicy.Route{Interface: name, Local: name == "lo"}, nil
	}
}

func tableResolver(names map[string][]string) Resolver {
	return func(_ context.Context, host string) ([]netip.Addr, error) {
		list, ok := names[host]
		if !ok {
			return nil, &net.DNSError{Err: "not found", Name: host, IsNotFound: true}
		}
		out := make([]netip.Addr, len(list))
		for i, s := range list {
			out[i] = netip.MustParseAddr(s)
		}
		return out, nil
	}
}

func message(err error) *string {
	if err == nil {
		return nil
	}
	_, _, msg := fault.Status(err)
	return &msg
}

func str(p *string) string {
	if p == nil {
		return "<nil>"
	}
	return *p
}

// TestPolicyMatchesPython runs validate, authorize (with the pinned
// address) and matches of the Python release (the saved-host check is
// validate; the script asserts that)
// against the Go policy for every case: five configurations, accounts by
// name, case and role, host spellings, ports and remote users, with a
// resolver and a route table that include dual-stack names, IPv4-mapped
// answers, this node's own address, duplicates and unrouted node
// addresses.
func TestPolicyMatchesPython(t *testing.T) {
	v := loadVectors(t)
	users := map[int64]User{}
	for _, u := range v.Users {
		users[u.ID] = User(u)
	}
	policies := make([]*Policy, len(v.Configs))
	for i, c := range v.Configs {
		cfg := Config{Enabled: c.Enabled, Interface: c.Interface, AllowedWebSSHUsers: c.Users, AllowedRemoteUsers: c.Remote}
		for _, pair := range c.Targets {
			cfg.AllowedTargets = append(cfg.AllowedTargets, Target{Host: pair[0].(string), Port: int(pair[1].(float64))})
		}
		policies[i] = New(cfg, tableResolver(v.Names), tableLookup(v.Routes))
	}
	for _, c := range v.Cases {
		p, u := policies[c.Config], users[c.User]
		name := strings.Join([]string{u.Username, c.Host, c.Remote}, "|")
		if got := message(p.Check(u, c.Host, c.Port, c.Remote)); str(got) != str(c.Check) {
			t.Errorf("config %d %q port %d check: python %s, go %s", c.Config, name, c.Port, str(c.Check), str(got))
			continue
		}
		a, err := p.Authorize(t.Context(), u, c.Host, c.Port, c.Remote)
		if str(message(err)) != str(c.Authorize) {
			t.Errorf("config %d %q port %d authorize: python %s, go %v", c.Config, name, c.Port, str(c.Authorize), err)
			continue
		}
		if err != nil {
			continue
		}
		if c.IP == nil || a.Addr().Addr().String() != *c.IP || int(a.Addr().Port()) != c.Port || a.Interface() != "tailscale0" {
			t.Errorf("config %d %q: python pins %s, go %v via %s", c.Config, name, str(c.IP), a.Addr(), a.Interface())
		}
		for kind, want := range c.Matches {
			host, port, remote, id := c.Host, c.Port, c.Remote, u.ID
			switch kind {
			case "other_user":
				id += 100
			case "other_port":
				port++
			case "other_remote":
				remote += "x"
			case "canonical":
				host, remote = strings.ToUpper(host)+".", " "+remote+" "
			}
			if got := a.Matches(id, host, port, remote); got != want {
				t.Errorf("config %d %q matches %s: python %v, go %v", c.Config, name, kind, want, got)
			}
		}
	}
}

func TestAuthorizationIsOnlyMintedByAuthorize(t *testing.T) {
	var zero Authorization
	if zero.Matches(0, "", 0, "") {
		t.Fatal("the zero authorization matches")
	}
	if _, err := zero.Variant().Dial(t.Context(), clientHop("", 0, "")); !errors.Is(err, ErrAuthorizationGone) {
		t.Fatalf("zero authorization dials: %v", err)
	}
}

func TestAuthorizeWithoutResolverRefusesNames(t *testing.T) {
	p := New(Config{Enabled: true, Interface: "tailscale0", AllowedTargets: []Target{{"node.lan", 22}}}, nil,
		tableLookup(map[string]string{}))
	if _, err := p.Authorize(t.Context(), User{ID: 1, IsAdmin: true}, "node.lan", 22, "u"); !errors.Is(err, ErrTargetNotAllowed) {
		t.Fatalf("name without resolver: %v", err)
	}
}

func TestPyStrip(t *testing.T) {
	for in, want := range map[string]string{" a ": "a", "\u3000a\u2028": "a", "\x1ca\u0085": "a", "a\u200b": "a\u200b", "\ufeffa": "\ufeffa"} {
		if got := pyStrip(in); got != want {
			t.Errorf("pyStrip(%q) = %q, want %q", in, got, want)
		}
	}
}
