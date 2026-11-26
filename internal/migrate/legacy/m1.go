package legacy

import (
	"context"
	"errors"
	"fmt"

	"github.com/bifrost0x/webssh/internal/accounts"
	"github.com/bifrost0x/webssh/internal/auth"
	"github.com/bifrost0x/webssh/internal/auth/local"
	"github.com/bifrost0x/webssh/internal/auth/totp"
	"github.com/bifrost0x/webssh/internal/hostops"
	"github.com/bifrost0x/webssh/internal/hosts"
	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/operations"
	"github.com/bifrost0x/webssh/internal/settings"
	"github.com/bifrost0x/webssh/internal/ssh/hostkey"
	"github.com/bifrost0x/webssh/internal/vault"
)

// M1 is what the steps of the M1 build need from the composition root.
type M1 struct {
	// AdminUsers is ADMIN_USERS; the migration applies Python's start-up
	// rules with it (specification 4.6).
	AdminUsers []string
	// Environment holds the boolean environment variables Python's
	// start-up migrations of app_settings.json read (E16).
	Environment settings.Environment
	// HostLimits are the store limits of saved hosts (E19 to E21).
	HostLimits hosts.Limits
	// BackupTempDir is BACKUP_TEMP_DIR, to count the backup operations
	// left in place (E39); empty counts none.
	BackupTempDir string
	// Passkeys stores migrated passkeys (internal/auth/webauthn). Without
	// it the passkeys stay in place and are pending (E10).
	Passkeys PasskeyStore
	// Persistent stores the persistent tmux sessions (internal/terminal).
	// Without it they stay in place and are pending (A01).
	Persistent PersistentSessionStore

	// wrap lets tests decorate every step (crash injection).
	wrap func(Step) Step
}

// RegisterM1 registers every entity of the migration specification for
// the M1 build: a step for each entity M1 migrates, discards or only
// accounts for, and the others as pending with the phase that migrates
// them. The registry then covers every entity.
func RegisterM1(r *Registry, m M1) error {
	if m.HostLimits == (hosts.Limits{}) {
		m.HostLimits = hosts.DefaultLimits
	}
	r.Schemas(accounts.Schema(), local.Schema(), auth.Schema(), totp.Schema(), operations.Schema(), settings.Schema(),
		vault.Schema(), hosts.Schema(), hostops.Schema(), hostkey.Schema())
	add := func(g Group, newStep func() Step) error {
		if m.wrap == nil {
			return r.Add(g, newStep)
		}
		return r.Add(g, func() Step { return m.wrap(newStep()) })
	}
	steps := []struct {
		group Group
		new   func() Step
	}{
		{GroupAccounts, func() Step { return &accountsStep{admins: m.AdminUsers} }},
		{GroupAccounts, func() Step { return &passwordsStep{} }},
		{GroupAccounts, func() Step { return &historyScopeStep{} }},
		{GroupAccounts, func() Step { return &quarantineStep{} }},
		{GroupFactors, func() Step { return &featureGatesStep{} }},
		{GroupFactors, func() Step { return &totpStep{} }},
		{GroupFactors, func() Step { return &recoveryCodesStep{} }},
		{GroupFactors, func() Step { return &transientStep{} }},
		{GroupFactors, func() Step { return &epochStep{} }},
		{GroupSettings, func() Step { return &appSettingsStep{env: m.Environment} }},
		{GroupSettings, func() Step { return &userSettingsStep{} }},
		{GroupSettings, func() Step { return &recoveryCheckStep{} }},
		{GroupKeys, func() Step { return &sshKeysStep{} }},
		{GroupHosts, func() Step { return &hostsStep{limits: m.HostLimits} }},
		{GroupHostTrust, func() Step { return &hostKeysStep{entity: "E17"} }},
		{GroupHostTrust, func() Step { return &hostKeysStep{entity: "E24"} }},
		{GroupHostContext, func() Step { return &hostNotesStep{} }},
		{GroupHostContext, func() Step { return &notepadStep{} }},
	}
	for _, d := range discardedEntities {
		steps = append(steps, struct {
			group Group
			new   func() Step
		}{GroupInventory, func() Step { return &discardStep{def: d} }})
	}
	for _, n := range notedEntities {
		steps = append(steps, struct {
			group Group
			new   func() Step
		}{GroupInventory, func() Step { return &notedStep{def: n} }})
	}
	for _, v := range hostPartEntities {
		steps = append(steps, struct {
			group Group
			new   func() Step
		}{GroupHosts, func() Step { return &hostPartStep{part: v} }})
	}
	var errs []error
	for _, s := range steps {
		errs = append(errs, add(s.group, s.new))
	}
	errs = append(errs, AddSingleUserStores(r))
	if m.Passkeys != nil {
		r.Schemas(m.Passkeys.Schema())
		errs = append(errs, add(GroupFactors, func() Step { return &passkeysStep{store: m.Passkeys} }))
	} else {
		errs = append(errs, r.KeepInPlace("E10", "D1", countPasskeys))
	}
	if m.Persistent != nil {
		r.Schemas(m.Persistent.Schema())
		errs = append(errs, add(GroupTerminal, func() Step { return &persistentSessionsStep{store: m.Persistent} }))
	} else {
		errs = append(errs, r.KeepInPlace("A01", "D6", countPersistentSessions))
	}
	for _, p := range pendingEntities(m.BackupTempDir) {
		errs = append(errs, r.KeepInPlace(p.entity, p.phase, p.count))
	}
	if err := errors.Join(errs...); err != nil {
		return err
	}
	if missing := r.Uncovered(); len(missing) > 0 {
		return fmt.Errorf("legacy: entities without a step or phase: %v", missing)
	}
	return nil
}

// ringOf returns the keyring behind the Sealer or Opener the framework
// passes; capability services that seal and open need the ring itself.
func ringOf(v any) (*keyring.Ring, error) {
	if r, ok := v.(*keyring.Ring); ok && r != nil {
		return r, nil
	}
	return nil, fmt.Errorf("legacy: the migration needs the keyring, got %T", v)
}

// accountIDs returns the ids of every account of the legacy database.
func accountIDs(ctx context.Context, src *Source) ([]AccountRow, map[int64]bool, error) {
	rows, err := src.AccountRows(ctx)
	if err != nil {
		return nil, nil, err
	}
	ids := make(map[int64]bool, len(rows))
	for _, a := range rows {
		ids[a.ID] = true
	}
	return rows, ids, nil
}
