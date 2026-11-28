package hosts

import (
	"context"
	"encoding/json/jsontext"

	"github.com/bifrost0x/webssh/internal/realtime/protocol"
	"github.com/bifrost0x/webssh/internal/store"
)

// Stored runs in the transaction that stores a saved host, jump host or
// SOCKS5 proxy, after the record is written, so that whatever belongs to
// the record (its saved password) is stored with it or not at all. saved
// is the stored record; an error stores nothing.
type Stored func(ctx context.Context, tx *store.Tx, saved jsontext.Value) error

var (
	errCreateOnly = invalid("A new record cannot name an existing one")
	errUpdateOnly = invalid("An edit must name the record it changes")
)

// CreateProfile creates a saved host as SaveProfile does and runs then in
// the same transaction.
func (s *Service) CreateProfile(ctx context.Context, owner int64, req protocol.HostsProfileSave, then Stored) (jsontext.Value, error) {
	if truthy(req.ID) {
		return nil, errCreateOnly
	}
	return s.saveProfile(ctx, owner, req, false, then)
}

// CreateJumpHost creates a jump host as SaveJumpHost does and runs then in
// the same transaction.
func (s *Service) CreateJumpHost(ctx context.Context, owner int64, req protocol.HostsJumpSave, then Stored) (jsontext.Value, error) {
	if len(req.JumpHostID) > 0 && !isNull(req.JumpHostID) {
		return nil, errCreateOnly
	}
	return s.saveJumpHost(ctx, owner, req, then)
}

// CreateSOCKSProxy creates a SOCKS5 proxy as SaveSOCKSProxy does and runs
// then in the same transaction.
func (s *Service) CreateSOCKSProxy(ctx context.Context, owner int64, req protocol.HostsSOCKSSave, then Stored) (jsontext.Value, error) {
	if len(req.SOCKSProxyID) > 0 && !isNull(req.SOCKSProxyID) {
		return nil, errCreateOnly
	}
	return s.saveSOCKSProxy(ctx, owner, req, then)
}

func runStored(ctx context.Context, tx *store.Tx, then Stored, saved record) error {
	if then == nil {
		return nil
	}
	return then(ctx, tx, saved.encode())
}

// UpdateProfile saves the edited host id as SaveProfile does and runs then
// in the same transaction.
func (s *Service) UpdateProfile(ctx context.Context, owner int64, id string, req protocol.HostsProfileSave, then Stored) (jsontext.Value, error) {
	if id == "" {
		return nil, errUpdateOnly
	}
	req.ID = jsonString(id)
	return s.saveProfile(ctx, owner, req, false, then)
}

// UpdateJumpHost saves the edited jump host id as SaveJumpHost does and
// runs then in the same transaction.
func (s *Service) UpdateJumpHost(ctx context.Context, owner int64, id string, req protocol.HostsJumpSave, then Stored) (jsontext.Value, error) {
	if id == "" {
		return nil, errUpdateOnly
	}
	req.JumpHostID = jsonString(id)
	return s.saveJumpHost(ctx, owner, req, then)
}

// UpdateSOCKSProxy saves the edited SOCKS5 proxy id as SaveSOCKSProxy does
// and runs then in the same transaction.
func (s *Service) UpdateSOCKSProxy(ctx context.Context, owner int64, id string, req protocol.HostsSOCKSSave, then Stored) (jsontext.Value, error) {
	if id == "" {
		return nil, errUpdateOnly
	}
	req.SOCKSProxyID = jsonString(id)
	return s.saveSOCKSProxy(ctx, owner, req, then)
}
