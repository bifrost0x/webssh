//go:build e2e

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base32"
	"encoding/hex"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/bifrost0x/webssh/internal/accounts"
	"github.com/bifrost0x/webssh/internal/auth/totp"
	"github.com/bifrost0x/webssh/internal/e2eseed"
	"github.com/bifrost0x/webssh/internal/hosts"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
	"github.com/bifrost0x/webssh/internal/store"
	"github.com/bifrost0x/webssh/internal/vault"
)

// e2eStores adapts the stores of the wired system to the seed applier.
// Nothing here is part of the release binary.
type e2eStores struct{ sys *system }

func (e e2eStores) stores() e2eseed.Stores {
	return e2eseed.Stores{
		Accounts: e, AppSettings: e.sys.settings, UserSettings: e.sys.settings,
		FeatureGates: e, Factors: e, Keys: e, Hosts: e,
	}
}

func (e e2eStores) CreateLocal(ctx context.Context, username, password string, admin bool) (int64, error) {
	a, err := e.sys.accounts.Create(ctx, accounts.CreateRequest{Username: username, Password: password, ByAdmin: true, Admin: admin})
	return a.ID, err
}

func (e e2eStores) MarkMFAEnabled(ctx context.Context, userID int64) error {
	return e.sys.db.Write(ctx, func(tx *store.Tx) error { return e.sys.accounts.SetMFARequiredTx(ctx, tx, userID, true) })
}

// SetFeature stores the administrator choice as the seed states it. Like
// run_app.py it records the choice without the readiness check of the
// admin route, so a seeded choice for a feature this build does not offer
// is kept and stays inactive.
func (e e2eStores) SetFeature(ctx context.Context, feature string, enabled bool, updatedBy int64) error {
	return e.sys.db.Write(ctx, func(tx *store.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO operations_feature_gates (feature, enabled, updated_by, updated_us) VALUES (?, ?, ?, ?)
			ON CONFLICT (feature) DO UPDATE SET enabled = excluded.enabled, updated_by = excluded.updated_by, updated_us = excluded.updated_us`,
			feature, enabled, updatedBy, time.Now().UnixMicro())
		return err
	})
}

// AddTOTPPlaceholder stores an authenticator with a random secret nobody
// knows: it marks the account as enrolled and never authenticates.
func (e e2eStores) AddTOTPPlaceholder(ctx context.Context, userID int64, label string, active bool) error {
	secret := make([]byte, 20)
	if _, err := rand.Read(secret); err != nil {
		return err
	}
	return e.sys.db.Write(ctx, func(tx *store.Tx) error {
		var id int64
		if err := tx.QueryRowContext(ctx, `SELECT coalesce(max(id), 0) + 1 FROM totp_authenticators`).Scan(&id); err != nil {
			return err
		}
		now := time.Now()
		a := totp.Imported{ID: id, UserID: userID, Label: label, Active: active, CreatedAt: now,
			Base32: base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)}
		if active {
			a.ActivatedAt = now
		}
		return e.sys.totp.ImportTx(ctx, tx, a)
	})
}

// AddPasskeyPlaceholder needs the passkey store; until that capability is
// in the build the placeholder is logged and not stored.
func (e e2eStores) AddPasskeyPlaceholder(ctx context.Context, userID int64, name, credentialID string, transports []string) error {
	if e.sys.optional.passkeyPlaceholder != nil {
		return e.sys.optional.passkeyPlaceholder(ctx, userID, name, credentialID, transports)
	}
	e.sys.log.Info("e2e: passkey placeholder skipped; passkeys are not in this build", "user_id", userID)
	return nil
}

func (e e2eStores) AddKey(ctx context.Context, owner int64, name string, key ed25519.PrivateKey) (string, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", err
	}
	id := randomUUID()
	block := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	err = e.sys.db.Write(ctx, func(tx *store.Tx) error {
		pub, err := vault.ImportKey(ctx, tx, e.sys.ring, vault.Imported{ID: id, UserID: owner, Name: name,
			KeyType: vault.KeyEd25519, UploadedAt: time.Now().UTC().Format(time.RFC3339), PEM: block})
		if err == nil && pub == "" {
			err = errors.New("generated key is not usable")
		}
		return err
	})
	return id, err
}

func (e e2eStores) AddJumpHost(ctx context.Context, owner int64, j e2eseed.JumpHostRecord) (string, error) {
	rec, err := e.sys.hosts.SaveJumpHost(ctx, owner, protocol.HostsJumpSave{Name: jv(j.Name), Host: jv(j.Host), Port: jv(j.Port),
		Username: jv(j.Username), AuthType: jv(j.Auth), KeyID: optionalString(j.KeyID)})
	if err != nil {
		return "", err
	}
	return recordID(rec)
}

func (e e2eStores) AddSOCKSProxy(ctx context.Context, owner int64, p e2eseed.SOCKSProxyRecord) (string, error) {
	rec, err := e.sys.hosts.SaveSOCKSProxy(ctx, owner, protocol.HostsSOCKSSave{Name: jv(p.Name), Host: jv(p.Host), Port: jv(p.Port),
		Username: jv(p.Username), AuthType: jv(p.Auth), RemoteDNS: jv(p.RemoteDNS)})
	if err != nil {
		return "", err
	}
	return recordID(rec)
}

// SaveProfiles stores the profiles as run_app.py builds them (_profile),
// keeping the jump hosts and proxies seeded before.
func (e e2eStores) SaveProfiles(ctx context.Context, owner int64, profiles []e2eseed.ProfileRecord) error {
	now := time.Now().UTC().Format("2006-01-02T15:04:05.000000+00:00")
	records := make([]jsontext.Value, 0, len(profiles))
	for _, p := range profiles {
		raw, err := json.Marshal(profileRecord(p, now))
		if err != nil {
			return err
		}
		records = append(records, raw)
	}
	return e.sys.db.Write(ctx, func(tx *store.Tx) error {
		cur, err := hosts.Export(ctx, tx, owner)
		if err != nil {
			return err
		}
		cur.Profiles = records
		_, err = hosts.Import(ctx, tx, owner, cur, e.sys.hosts.Limits)
		return err
	})
}

func profileRecord(p e2eseed.ProfileRecord, now string) map[string]any {
	port := p.Port
	if port == 0 {
		port = 22
	}
	r := map[string]any{"id": p.ID, "name": p.Name, "host": p.Host, "port": port, "username": p.Username,
		"auth_type": p.Auth, "key_id": nil, "startup_mode": "none", "created_at": now, "updated_at": now}
	set := func(k, v string) {
		if v != "" {
			r[k] = v
		}
	}
	set("key_id", p.KeyID)
	set("group", p.Group)
	set("jump_host_id", p.JumpHostID)
	set("socks_proxy_id", p.SOCKSProxyID)
	set("startup_mode", p.StartupMode)
	set("startup_commands", p.StartupCommands)
	set("command_id", p.CommandID)
	set("command_set_id", p.CommandSetID)
	if p.SortOrder != nil {
		r["sort_order"] = *p.SortOrder
	}
	if p.Favorite {
		r["favorite"] = true
	}
	if p.ParametersOverride != nil {
		r["parameters_override"] = *p.ParametersOverride
	}
	return r
}

func jv(v any) jsontext.Value {
	raw, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("e2e: encode %v: %v", v, err))
	}
	return raw
}

func optionalString(s string) jsontext.Value {
	if s == "" {
		return nil
	}
	return jv(s)
}

func recordID(rec jsontext.Value) (string, error) {
	var r struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(rec, &r); err != nil || r.ID == "" {
		return "", fmt.Errorf("e2e: saved record without id: %w", err)
	}
	return r.ID, nil
}

func randomUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b)
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}
