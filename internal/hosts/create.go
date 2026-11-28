package hosts

import (
	"context"
	"encoding/json/jsontext"

	"github.com/bifrost0x/webssh/internal/realtime/protocol"
	"github.com/bifrost0x/webssh/internal/store"
)

// Created runs in the transaction that stores a new saved host, jump host
// or SOCKS5 proxy, after the record is written, so that whatever belongs
// to the record (its saved password) is stored with it or not at all. saved
// is the stored record; an error stores nothing.
type Created func(ctx context.Context, tx *store.Tx, saved jsontext.Value) error

var errCreateOnly = invalid("A new record cannot name an existing one")

// CreateProfile creates a saved host as SaveProfile does and runs then in
// the same transaction.
func (s *Service) CreateProfile(ctx context.Context, owner int64, req protocol.HostsProfileSave, then Created) (jsontext.Value, error) {
	if truthy(req.ID) {
		return nil, errCreateOnly
	}
	return s.saveProfile(ctx, owner, req, false, then)
}

// CreateJumpHost creates a jump host as SaveJumpHost does and runs then in
// the same transaction.
func (s *Service) CreateJumpHost(ctx context.Context, owner int64, req protocol.HostsJumpSave, then Created) (jsontext.Value, error) {
	if len(req.JumpHostID) > 0 && !isNull(req.JumpHostID) {
		return nil, errCreateOnly
	}
	return s.saveJumpHost(ctx, owner, req, then)
}

// CreateSOCKSProxy creates a SOCKS5 proxy as SaveSOCKSProxy does and runs
// then in the same transaction.
func (s *Service) CreateSOCKSProxy(ctx context.Context, owner int64, req protocol.HostsSOCKSSave, then Created) (jsontext.Value, error) {
	if len(req.SOCKSProxyID) > 0 && !isNull(req.SOCKSProxyID) {
		return nil, errCreateOnly
	}
	return s.saveSOCKSProxy(ctx, owner, req, then)
}

func runCreated(ctx context.Context, tx *store.Tx, then Created, saved record) error {
	if then == nil {
		return nil
	}
	return then(ctx, tx, saved.encode())
}
