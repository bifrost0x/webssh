package main

import (
	"os"
	"path/filepath"
	"strconv"

	"github.com/bifrost0x/webssh/internal/accounts"
	"github.com/bifrost0x/webssh/internal/audit"
	"github.com/bifrost0x/webssh/internal/auth"
	"github.com/bifrost0x/webssh/internal/operations"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/session"
	"github.com/bifrost0x/webssh/internal/terminal"
)

// accountsArea wires the area "accounts" (ID4): account administration (internal/accounts, internal/auth, internal/session).
// ID4 fills in the hooks; no other package edits this file.
func accountsArea() extension {
	return extension{name: "accounts", wire: wireAccounts}
}

// The providers satisfy the consumer interfaces of the area.
var (
	_ accounts.Sessions      = (*session.Service)(nil)
	_ accounts.RecoveryCodes = (*auth.Recovery)(nil)
	_ accounts.Warner        = (*audit.Logger)(nil)
	_ accounts.Gates         = (*operations.Gates)(nil)
	_ accounts.LiveAccess    = terminalAccess{}
)

// terminalAccess ends the terminals and persistent tmux sessions of an
// account that has no browser session left. The terminal reacts to an
// account-wide revocation as to the end of the account's last session.
type terminalAccess struct{ m *terminal.Manager }

func (t terminalAccess) EndAccount(userID int64, reason principal.Reason) {
	if t.m != nil {
		t.m.Revoked(principal.Revocation{UserID: userID, Reason: reason})
	}
}

// legacyUserDir reports the Python data directory of a user id in
// DATA_DIR, which a deletion records in the quarantine index and never
// changes (I-01).
func legacyUserDir(dataDir string) accounts.LegacyUserDir {
	return func(id int64) (string, bool) {
		rel := filepath.ToSlash(filepath.Join("users", "user_"+strconv.FormatInt(id, 10)))
		info, err := os.Lstat(filepath.Join(dataDir, filepath.FromSlash(rel)))
		return rel, err == nil && info.IsDir()
	}
}

// wireAccounts hands the account service what it ends and removes, and
// registers the administration routes and the retired stand-alone
// recovery sign-in.
func wireAccounts(sys *system) error {
	a := sys.accounts
	a.Sessions = sys.sessions
	a.Live = terminalAccess{sys.terminal}
	a.Data = accounts.TableSweep{Keep: accounts.DefaultKeep}
	a.Factors = accounts.TableReset{Tables: accounts.FactorTables}
	a.Recovery = sys.recovery
	a.LegacyDir = legacyUserDir(sys.cfg.DataDir)
	(&accounts.HTTP{Accounts: a, StepUp: sys.stepup, Gates: sys.gates, Enabled: sys.cfg.Accounts.AdminPanelEnabled,
		Logger: sys.log}).RegisterAdmin(sys.edge.Mux())
	(&auth.FactorHTTP{MFA: sys.mfa, Logger: sys.log}).RegisterRecoveryCompat(sys.edge.Mux())
	return nil
}
