package hosts

import (
	"context"

	"github.com/bifrost0x/webssh/internal/ssh/client"
	"github.com/bifrost0x/webssh/internal/store"
)

// JumpHost returns a saved jump host of owner as the first hop of a
// connection typed by hand (terminal.SavedRoutes). The same rules as for a
// saved host apply: only key sign-in is offered in this preview, and the
// address is validated as stored.
func (s *Service) JumpHost(ctx context.Context, owner int64, jumpHostID string) (client.Hop, error) {
	var hop client.Hop
	err := s.DB.Read(ctx, func(tx *store.Tx) error {
		all, err := loadStores(ctx, tx, owner)
		if err != nil {
			return err
		}
		jumps := all["jump_hosts"]
		i := find(jumps, jumpHostID)
		if i < 0 {
			return errJumpNotFound
		}
		if jumps[i].text("auth_type") != "key" {
			return errJumpPasswordPreview
		}
		hop, err = hopOf(&jumps[i])
		return err
	})
	if err != nil {
		return client.Hop{}, classify(err, "Failed to load jump hosts")
	}
	return hop, nil
}

// SOCKSProxy returns a saved SOCKS5 proxy of owner for a connection typed
// by hand (terminal.SavedRoutes). Proxies with a login are not offered in
// this preview.
func (s *Service) SOCKSProxy(ctx context.Context, owner int64, socksProxyID string) (client.SOCKS, error) {
	var proxy client.SOCKS
	err := s.DB.Read(ctx, func(tx *store.Tx) error {
		all, err := loadStores(ctx, tx, owner)
		if err != nil {
			return err
		}
		proxies := all["socks_proxies"]
		i := find(proxies, socksProxyID)
		if i < 0 {
			return errSOCKSNotFound
		}
		p := &proxies[i]
		if p.text("auth_type") != "none" {
			return errSOCKSPasswordPreview
		}
		host, port, err := address(p)
		if err != nil {
			return err
		}
		remoteDNS, _ := p.get("remote_dns")
		proxy = client.SOCKS{Host: host, Port: port, RemoteDNS: string(remoteDNS) == "true"}
		return nil
	})
	if err != nil {
		return client.SOCKS{}, classify(err, "Failed to load SOCKS5 proxies")
	}
	return proxy, nil
}
