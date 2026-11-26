package hosts

import (
	"context"
	"strings"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/ssh/client"
	"github.com/bifrost0x/webssh/internal/store"
)

var (
	errJumpPasswordPreview  = fault.New(fault.NotAvailableInPreview, "Jump hosts with password sign-in are not available in this preview.")
	errSOCKSPasswordPreview = fault.New(fault.NotAvailableInPreview, "SOCKS5 proxies with a login are not available in this preview.")
	errTailscaleConnect     = fault.New(fault.NotAvailableInPreview, "Tailscale SSH is not available in this preview.")
)

// Resolve returns the connection target of a saved host of owner, read
// from the stores at this moment (terminal.Profiles). The password of the
// target hop, if any, comes with the request; everything else is taken
// from the saved records, never from the browser. It fails with not_found
// for a host, jump host or proxy that does not exist for owner, and with
// not_available_in_preview for routes this release does not build.
func (s *Service) Resolve(ctx context.Context, owner int64, profileID string) (client.Target, error) {
	var t client.Target
	err := s.DB.Read(ctx, func(tx *store.Tx) error {
		all, err := loadStores(ctx, tx, owner)
		if err != nil {
			return err
		}
		t, err = resolve(all, owner, profileID, s.Variants != nil)
		return err
	})
	if err != nil {
		return client.Target{}, classify(err, "Failed to load profiles")
	}
	return t, nil
}

func resolve(all stores, owner int64, profileID string, variants bool) (client.Target, error) {
	profiles := all["profiles"]
	index := find(profiles, profileID)
	if index < 0 {
		return client.Target{}, errProfileNotFound
	}
	p := &profiles[index]
	tailscale := false
	switch p.text("auth_type") {
	case "tailscale":
		tailscale = true
		if !variants {
			return client.Target{}, errTailscaleConnect
		}
	case "password", "key":
	default:
		return client.Target{}, invalid("Invalid auth_type")
	}
	if strings.Contains(p.text("username"), ":") && !variants {
		return client.Target{}, errGatewayPreview
	}
	hop, err := hopOf(p)
	if err != nil {
		return client.Target{}, err
	}
	if jump, _ := p.get("jump_host_id"); tailscale && truthy(jump) {
		return client.Target{}, invalid("Tailscale SSH cannot be used with a jump host")
	}
	if socks, _ := p.get("socks_proxy_id"); tailscale && truthy(socks) {
		return client.Target{}, invalid("Tailscale SSH cannot be used with a SOCKS5 proxy")
	}
	mode, _ := startupMode(p.get)
	useTmux, _ := p.get("use_tmux")
	useHerdr, _ := p.get("use_herdr")
	t := client.Target{
		Owner: owner,
		Hop:   hop,
		Display: client.Display{
			ProfileID:      profileID,
			Name:           p.text("name"),
			UseTmux:        string(useTmux) == "true",
			UseHerdr:       string(useHerdr) == "true",
			StartupCommand: string(mode) != `"none"`,
			Tailscale:      tailscale,
		},
	}
	if id, _ := p.str("jump_host_id"); id != "" {
		jumps := all["jump_hosts"]
		j := find(jumps, id)
		if j < 0 {
			return client.Target{}, errJumpNotFound
		}
		if jumps[j].text("auth_type") != "key" {
			return client.Target{}, errJumpPasswordPreview
		}
		jump, err := hopOf(&jumps[j])
		if err != nil {
			return client.Target{}, err
		}
		t.Jumps = []client.Hop{jump}
		t.Display.JumpHostID = id
	}
	if id, _ := p.str("socks_proxy_id"); id != "" {
		proxies := all["socks_proxies"]
		j := find(proxies, id)
		if j < 0 {
			return client.Target{}, errSOCKSNotFound
		}
		proxy := &proxies[j]
		if proxy.text("auth_type") != "none" {
			return client.Target{}, errSOCKSPasswordPreview
		}
		host, port, err := address(proxy)
		if err != nil {
			return client.Target{}, err
		}
		remoteDNS, _ := proxy.get("remote_dns")
		t.Proxy = &client.SOCKS{Host: host, Port: port, RemoteDNS: string(remoteDNS) == "true"}
		t.Display.SOCKSProxyID = id
	}
	return t, nil
}

// hopOf is one SSH hop of a saved host or jump host. The host is the
// stored name; host keys are kept under it.
func hopOf(r *record) (client.Hop, error) {
	host, port, err := address(r)
	if err != nil {
		return client.Hop{}, err
	}
	hop := client.Hop{Host: host, Port: port, User: r.text("username")}
	if r.text("auth_type") == "key" {
		hop.Auth.KeyID = r.text("key_id")
		if hop.Auth.KeyID == "" {
			return client.Hop{}, invalid("key_id required for key authentication")
		}
	}
	return hop, nil
}

func address(r *record) (string, int, error) {
	host := r.text("host")
	if NeedsIDNA(host) {
		return "", 0, errHostIDNA
	}
	if !validHost(host) {
		return "", 0, invalid("Invalid host format")
	}
	port := int64(22)
	if v, ok := r.get("port"); ok {
		n, isInt := asInt(v)
		if !isInt || n < 1 || n > 65535 {
			return "", 0, invalid("Port must be between 1 and 65535")
		}
		port = n
	}
	return pyStrip(host), int(port), nil
}

// Endpoint is one SSH endpoint of a user, a saved host ("ssh") or a jump
// host ("jump"). It has the fields of hostkey.Target; the composition root
// passes the list to internal/ssh/hostkey, which this package may not
// import.
type Endpoint struct {
	ID   string
	Name string
	Kind string
	Host string
	Port int
}

// SSHTargets lists the endpoints whose host-key trust the host-key views
// explain: every saved host, then every jump host, as stored. Hosts never
// come from a request, so a global wildcard cannot become an inventory
// oracle.
func (s *Service) SSHTargets(ctx context.Context, owner int64) ([]Endpoint, error) {
	var out []Endpoint
	err := s.DB.Read(ctx, func(tx *store.Tx) error {
		all, err := loadStores(ctx, tx, owner)
		if err != nil {
			return err
		}
		for _, c := range []struct{ key, kind string }{{"profiles", "ssh"}, {"jump_hosts", "jump"}} {
			for i := range all[c.key] {
				r := &all[c.key][i]
				port := 22
				if v, ok := r.get("port"); ok && truthy(v) {
					if n, ok := asInt(v); ok && n >= 1 && n <= 65535 {
						port = int(n)
					}
				}
				out = append(out, Endpoint{ID: r.text("id"), Name: r.text("name"), Kind: c.kind, Host: r.text("host"), Port: port})
			}
		}
		return nil
	})
	if err != nil {
		return nil, classify(err, "Failed to load profiles")
	}
	return out, nil
}
