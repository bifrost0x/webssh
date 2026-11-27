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
	"github.com/bifrost0x/webssh/internal/hosts"
	"github.com/bifrost0x/webssh/internal/httpapi"
	"github.com/bifrost0x/webssh/internal/migrate/legacy"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
	"github.com/bifrost0x/webssh/internal/settings"
	"github.com/bifrost0x/webssh/internal/store"
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
				Writer:   credentialResources{hosts: sys.hosts},
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
	_ vault.Stores         = credentialStores{}
	_ vault.ResourceWriter = credentialResources{}
	_ vault.Policy         = credentialPolicy{}
	_ vault.Incarnations   = credentialAccounts{}
	_ vault.Audit          = credentialAudit{}
	_ vault.Resources      = (*vault.Service)(nil)
)

// credentialStores reads the saved hosts, jump hosts and SOCKS proxies of
// a user in one snapshot. SMB shares join with internal/files/smb (FS3);
// until then their assignments are kept and count as in use.
type credentialStores struct{ db *store.DB }

func (c credentialStores) Records(ctx context.Context, userID int64) (vault.Records, error) {
	var l hosts.Legacy
	err := c.db.Read(ctx, func(tx *store.Tx) error {
		var err error
		l, err = hosts.Export(ctx, tx, userID)
		return err
	})
	return vault.Records{Profiles: l.Profiles, JumpHosts: l.JumpHosts, SOCKSProxies: l.SOCKSProxies}, err
}

// credentialResources creates and removes saved hosts, jump hosts and
// SOCKS proxies through their own save, for a resource created together
// with its password.
type credentialResources struct{ hosts *hosts.Service }

func (c credentialResources) CreateResource(ctx context.Context, userID int64, kind vault.ResourceKind, payload jsontext.Value) (jsontext.Value, error) {
	switch kind {
	case vault.ResourceSSH:
		var req protocol.HostsProfileSave
		if err := json.Unmarshal(payload, &req); err != nil {
			return nil, fault.New(fault.InvalidRequest, "")
		}
		return c.hosts.SaveProfile(ctx, userID, req)
	case vault.ResourceJump:
		var req protocol.HostsJumpSave
		if err := json.Unmarshal(payload, &req); err != nil {
			return nil, fault.New(fault.InvalidRequest, "")
		}
		return c.hosts.SaveJumpHost(ctx, userID, req)
	case vault.ResourceSOCKS:
		var req protocol.HostsSOCKSSave
		if err := json.Unmarshal(payload, &req); err != nil {
			return nil, fault.New(fault.InvalidRequest, "")
		}
		return c.hosts.SaveSOCKSProxy(ctx, userID, req)
	}
	return nil, fault.New(fault.NotAvailableInPreview, "")
}

func (c credentialResources) DeleteResource(ctx context.Context, userID int64, kind vault.ResourceKind, recordID string) error {
	quoted, err := json.Marshal(recordID)
	if err != nil {
		return err
	}
	id := jsontext.Value(quoted)
	switch kind {
	case vault.ResourceSSH:
		return c.hosts.DeleteProfile(ctx, userID, id)
	case vault.ResourceJump:
		return c.hosts.DeleteJumpHost(ctx, userID, id)
	case vault.ResourceSOCKS:
		return c.hosts.DeleteSOCKSProxy(ctx, userID, id)
	}
	return nil
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

// savedPasswords adapts the vault to the terminal's saved passwords
// (terminal.SavedPasswords of NW1, wired when the areas are merged): the
// password assigned to a saved host, jump host or SOCKS proxy, checked
// against the resource as it is now.
type savedPasswords struct{ vault *vault.Service }

func (s savedPasswords) Password(ctx context.Context, owner int64, resourceID string) (string, error) {
	t, found, err := s.vault.Resource(ctx, owner, resourceID)
	if err != nil {
		return "", err
	}
	if !found {
		return "", fault.New(fault.CredentialMissing, "")
	}
	secret, err := s.vault.Password(ctx, owner, resourceID, t)
	if err != nil {
		return "", err
	}
	defer clear(secret)
	return string(secret), nil
}

// TargetPassword is the password of Quick Connect without a saved host:
// the target token of /api/credentials/authorize-target
// (credential_target_token) for exactly this host, port, user and route.
func (s savedPasswords) TargetPassword(ctx context.Context, p principal.Principal, credentialID, token string, host string, port int, user, jumpHostID, socksProxyID string) (string, error) {
	port64, auth := int64(port), "password"
	t := vault.Target{Kind: vault.ResourceSSH, Host: &host, Port: &port64, Username: &user, AuthType: &auth}
	if jumpHostID != "" {
		t.JumpHostID = &jumpHostID
	}
	if socksProxyID != "" {
		t.SOCKSProxyID = &socksProxyID
	}
	secret, err := s.vault.TargetPassword(ctx, p, credentialID, token, t)
	if err != nil {
		return "", err
	}
	defer clear(secret)
	return string(secret), nil
}
