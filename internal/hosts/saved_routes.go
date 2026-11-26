package hosts

import (
	"context"

	"github.com/bifrost0x/webssh/internal/ssh/client"
	"github.com/bifrost0x/webssh/internal/store"
)

// JumpHost returns a saved jump host of owner as the first hop of a
// connection typed by hand (terminal.SavedRoutes). The same rules as for a
// saved host apply: the address is validated as stored, and a jump host
// with password sign-in gets its password from the caller.
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
		hop, err = jumpHopOf(&jumps[i])
		return err
	})
	if err != nil {
		return client.Hop{}, classify(err, "Failed to load jump hosts")
	}
	return hop, nil
}

// SOCKSProxy returns a saved SOCKS5 proxy of owner for a connection typed
// by hand (terminal.SavedRoutes). A proxy with a login carries its
// username; the caller adds the password.
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
		proxy, err = socksOf(&proxies[i])
		return err
	})
	if err != nil {
		return client.SOCKS{}, classify(err, "Failed to load SOCKS5 proxies")
	}
	return proxy, nil
}
