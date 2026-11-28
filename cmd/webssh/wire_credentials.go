package main

import (
	"context"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"net/http"

	"github.com/bifrost0x/webssh/internal/accounts"
	"github.com/bifrost0x/webssh/internal/audit"
	"github.com/bifrost0x/webssh/internal/config"
	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/files/smb"
	"github.com/bifrost0x/webssh/internal/hosts"
	"github.com/bifrost0x/webssh/internal/httpapi"
	"github.com/bifrost0x/webssh/internal/migrate/legacy"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
	"github.com/bifrost0x/webssh/internal/settings"
	"github.com/bifrost0x/webssh/internal/store"
	"github.com/bifrost0x/webssh/internal/terminal"
	"github.com/bifrost0x/webssh/internal/vault"
)

// credentialsArea wires the area "credentials" (VA1): saved credentials and the legacy automation vault (internal/vault).
// VA1 fills in the hooks; no other package edits this file.
func credentialsArea() extension {
	return extension{
		name: "credentials",
		wire: func(sys *system) error {
			if err := sys.vault.EnableCredentials(vault.CredentialOptions{
				Stores:   credentialStores{db: sys.db},
				Writer:   credentialResources{hosts: sys.hosts, shares: &smb.Shares{DB: sys.db, Max: sys.cfg.SMB.MaxSavedShares}},
				Policy:   credentialPolicy{sys.settings},
				Accounts: credentialAccounts{sys.accounts},
				Audit:    credentialAudit{sys.audit},
			}); err != nil {
				return err
			}
			(&vault.CredentialsHTTP{Service: sys.vault, HTTPS: httpapi.ReachedOverHTTPS,
				Index: func(r *http.Request) string { return httpapi.BasePath(r) + "/" }, Logger: sys.log}).Register(sys.edge.Mux())
			return nil
		},
		background: func(ctx context.Context, sys *system) {
			sys.background.Go(func() {
				sys.every(ctx, vault.SweepInterval, func(context.Context) bool {
					sys.vault.Sweep()
					return true
				})
			})
		},
		migrate: func(r *legacy.Registry, _ config.Config, _ config.LookupFunc) error {
			return legacy.AddCredentials(r)
		},
	}
}

// The providers satisfy the consumer interfaces of the area.
var (
	_ vault.Stores            = credentialStores{}
	_ vault.ResourceWriter    = credentialResources{}
	_ vault.Policy            = credentialPolicy{}
	_ vault.Incarnations      = credentialAccounts{}
	_ vault.Audit             = credentialAudit{}
	_ vault.Resources         = (*vault.Service)(nil)
	_ terminal.SavedPasswords = savedPasswords{}
	_ smb.Passwords           = savedPasswords{}
)

// credentialStores reads the saved hosts, jump hosts, SOCKS proxies and
// SMB shares of a user in one snapshot. The share definitions are stored
// whether SMB_ENABLED is on or not, as in the Python release.
type credentialStores struct{ db *store.DB }

func (c credentialStores) Records(ctx context.Context, userID int64) (vault.Records, error) {
	var r vault.Records
	err := c.db.Read(ctx, func(tx *store.Tx) error {
		var err error
		r, err = credentialRecordsTx(ctx, tx, userID)
		return err
	})
	return r, err
}

func credentialRecordsTx(ctx context.Context, tx *store.Tx, userID int64) (vault.Records, error) {
	l, err := hosts.Export(ctx, tx, userID)
	if err != nil {
		return vault.Records{}, err
	}
	shares, err := smb.SharesTx(ctx, tx, userID)
	if err != nil {
		return vault.Records{}, err
	}
	return vault.Records{Profiles: l.Profiles, JumpHosts: l.JumpHosts, SOCKSProxies: l.SOCKSProxies,
		SMBShares: shares, SMB: true}, nil
}

// credentialResources creates saved hosts, jump hosts, SOCKS proxies and
// SMB shares through their own save, for a resource created together with
// its password: the vault's assignment runs in the transaction that stores
// the record and sees the records of that transaction.
type credentialResources struct {
	hosts  *hosts.Service
	shares *smb.Shares
}

func (c credentialResources) CreateResource(ctx context.Context, userID int64, kind vault.ResourceKind, payload jsontext.Value, within vault.Within) (jsontext.Value, error) {
	then := func(ctx context.Context, tx *store.Tx, saved jsontext.Value) error {
		records, err := credentialRecordsTx(ctx, tx, userID)
		if err != nil {
			return err
		}
		return within(ctx, tx, saved, records)
	}
	switch kind {
	case vault.ResourceSSH:
		var req protocol.HostsProfileSave
		if err := json.Unmarshal(payload, &req); err != nil {
			return nil, fault.New(fault.InvalidRequest, "")
		}
		return c.hosts.CreateProfile(ctx, userID, req, then)
	case vault.ResourceJump:
		var req protocol.HostsJumpSave
		if err := json.Unmarshal(payload, &req); err != nil {
			return nil, fault.New(fault.InvalidRequest, "")
		}
		return c.hosts.CreateJumpHost(ctx, userID, req, then)
	case vault.ResourceSOCKS:
		var req protocol.HostsSOCKSSave
		if err := json.Unmarshal(payload, &req); err != nil {
			return nil, fault.New(fault.InvalidRequest, "")
		}
		return c.hosts.CreateSOCKSProxy(ctx, userID, req, then)
	case vault.ResourceSMB:
		req, err := smb.SaveRequestOf(payload)
		if err != nil {
			return nil, err
		}
		return c.shares.Create(ctx, userID, req, then)
	}
	return nil, fault.New(fault.NotAvailableInPreview, "")
}

type credentialPolicy struct{ settings *settings.Service }

func (c credentialPolicy) CredentialsPolicy(ctx context.Context) (bool, string, error) {
	app, err := c.settings.App(ctx)
	return app.CredentialsEnabled, app.CredentialsRevision, err
}

type credentialAccounts struct{ accounts *accounts.Service }

func (c credentialAccounts) Incarnation(ctx context.Context, userID int64) (string, error) {
	a, err := c.accounts.Get(ctx, userID)
	return a.Incarnation, err
}

type credentialAudit struct{ log *audit.Logger }

// CredentialChanged writes the CREDENTIAL_CHANGED event of the Python
// release; it names the action, never a secret.
func (c credentialAudit) CredentialChanged(_ context.Context, userID int64, action string) {
	if c.log != nil {
		c.log.Event(audit.Info, "CREDENTIAL_CHANGED", audit.F("user_id", userID), audit.F("action", action))
	}
}
