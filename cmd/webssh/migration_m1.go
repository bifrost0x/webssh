package main

import (
	"context"
	"errors"

	"github.com/bifrost0x/webssh/internal/config"
	"github.com/bifrost0x/webssh/internal/hosts"
	"github.com/bifrost0x/webssh/internal/migrate/legacy"
	"github.com/bifrost0x/webssh/internal/store"
	"github.com/bifrost0x/webssh/internal/terminal"
)

// The migration steps of M1: every entity of the specification is a step
// or pending with the phase that migrates it.
func init() {
	migrationRegistrar = func(r *legacy.Registry, cfg config.Config, lookup config.LookupFunc) error {
		return legacy.RegisterM1(r, legacy.M1{
			AdminUsers:    cfg.Accounts.AdminUsers,
			Environment:   settingsEnvironment(cfg, lookup),
			HostLimits:    hostLimits(cfg),
			BackupTempDir: cfg.BackupTempDir,
			Persistent:    persistentSessions{},
		})
	}
}

func hostLimits(cfg config.Config) hosts.Limits {
	return hosts.Limits{ProfileMaxRecords: cfg.Stores.ProfileMaxRecords, JumpHostMaxRecords: cfg.Stores.JumpHostMaxRecords,
		SOCKSProxyMaxRecords: cfg.Stores.SOCKSProxyMaxRecords, StoreMaxBytes: cfg.Stores.ConnectionStoreMaxBytes,
		ConfigMaxBytes: cfg.Stores.ConnectionConfigMaxBytes}
}

// persistentSessions hands the persistent tmux sessions (A01) to the
// terminal's store, keeping the legacy row id.
type persistentSessions struct{}

var _ legacy.PersistentSessionStore = persistentSessions{}

func (persistentSessions) Schema() store.Schema { return terminal.Schema() }

func (persistentSessions) ImportPersistentTx(ctx context.Context, tx *store.Tx, p legacy.PersistentSession) error {
	return terminal.ImportPersistentAt(ctx, tx, p.RowID, terminal.PersistentRow{
		SessionID: p.SessionID, UserID: p.UserID, Host: p.Host, Port: p.Port, Username: p.Username, KeyID: p.KeyID,
		AuthType: p.AuthType, TmuxSessionName: p.TmuxSessionName, DisplayName: p.DisplayName, JumpHostID: p.JumpHostID,
		SOCKSProxyID: p.SOCKSProxyID, ViaSOCKS: p.ViaSOCKS, ProfileID: p.ProfileID, ViaJump: p.ViaJump,
		ReconnectRouteKnown: p.ReconnectRouteKnown, CreatedAt: p.CreatedAt, LastActivity: p.LastActivity,
	})
}

// PersistentTx reads the rows back for the verification. A row the
// import marked connected would not compare equal: connected has no
// legacy column, so it is checked here.
func (persistentSessions) PersistentTx(ctx context.Context, tx *store.Tx) ([]legacy.PersistentSession, error) {
	rows, err := terminal.ImportedPersistentTx(ctx, tx)
	if err != nil {
		return nil, err
	}
	out := make([]legacy.PersistentSession, 0, len(rows))
	for _, ip := range rows {
		r := ip.Row
		if r.Connected {
			return nil, errConnectedImport
		}
		out = append(out, legacy.PersistentSession{
			RowID: ip.ID, SessionID: r.SessionID, UserID: r.UserID, Host: r.Host, Port: r.Port, Username: r.Username,
			KeyID: r.KeyID, AuthType: r.AuthType, TmuxSessionName: r.TmuxSessionName, DisplayName: r.DisplayName,
			JumpHostID: r.JumpHostID, SOCKSProxyID: r.SOCKSProxyID, ViaSOCKS: r.ViaSOCKS, ProfileID: r.ProfileID,
			ViaJump: r.ViaJump, ReconnectRouteKnown: r.ReconnectRouteKnown, CreatedAt: r.CreatedAt, LastActivity: r.LastActivity,
		})
	}
	return out, nil
}

var errConnectedImport = errors.New("webssh: a migrated persistent session is marked connected")
