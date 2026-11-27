package terminal

import (
	"context"

	"github.com/bifrost0x/webssh/internal/realtime/protocol"
	"github.com/bifrost0x/webssh/internal/ssh/client"
)

// Target checks and resolves a connection request like terminal.open
// (saved host, typed target, jump host or SOCKS5 proxy, saved passwords
// with their guard), for connections that are not a terminal (Quick SFTP).
func (m *Manager) Target(ctx context.Context, owner int64, req protocol.OpenTarget) (client.Target, error) {
	return m.resolve(ctx, owner, req)
}

// Interaction asks the user of peer about host keys and banners of a
// connection attempt with the terminal's prompts; requestID correlates
// them (Quick SFTP asks like the terminal, D-22).
func (m *Manager) Interaction(peer protocol.Peer, requestID string) client.Interaction {
	return &interaction{m: m, peer: peer, owner: peer.Principal().UserID, requestID: requestID}
}
