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
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"time"

	"github.com/bifrost0x/webssh/internal/accounts"
	"github.com/bifrost0x/webssh/internal/auth"
	"github.com/bifrost0x/webssh/internal/auth/github"
	"github.com/bifrost0x/webssh/internal/auth/oidc"
	"github.com/bifrost0x/webssh/internal/auth/totp"
	"github.com/bifrost0x/webssh/internal/e2eseed"
	"github.com/bifrost0x/webssh/internal/hosts"
	"github.com/bifrost0x/webssh/internal/httpapi"
	"github.com/bifrost0x/webssh/internal/netpolicy"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
	"github.com/bifrost0x/webssh/internal/ssh/client"
	"github.com/bifrost0x/webssh/internal/store"
	"github.com/bifrost0x/webssh/internal/vault"
)

// Test-only switches of the end-to-end suite (tests/e2e/README.md). They
// are read here and nowhere else.
const (
	envE2EPort        = "WEBSSH_E2E_PORT"
	envE2ESeed        = "WEBSSH_E2E_SEED"
	envE2EFastHashing = "WEBSSH_E2E_FAST_HASHING"
	defaultE2ESeed    = "tests/e2e/seed.json"
)

func init() { e2eCommand = runE2E }

// runE2E starts the disposable backend of the browser suite:
//
//	WEBSSH_E2E_SERVER_COMMAND='go run -tags e2e ./cmd/webssh e2e'
func runE2E(args []string, _, stderr io.Writer) int {
	if len(args) > 0 {
		return usageError(stderr, "e2e takes no arguments")
	}
	log := slog.New(slog.NewTextHandler(stderr, nil))
	port, err := e2eseed.ParsePort(os.Getenv(envE2EPort))
	if err != nil {
		log.Error("e2e backend", "error", err)
		return 2
	}
	seed := os.Getenv(envE2ESeed)
	if seed == "" {
		seed = defaultE2ESeed
	}
	opts := e2eseed.Options{
		SeedPath:    seed,
		Port:        port,
		FastHashing: os.Getenv(envE2EFastHashing) == "1",
		Environ:     os.Environ(),
		Log:         log,
	}
	// Playwright stops the server with SIGKILL unless the config asks for
	// a graceful shutdown; an interrupt ends the run and removes the
	// scratch tree.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := e2eseed.Run(ctx, opts, wireE2E); err != nil {
		log.Error("e2e backend", "error", err)
		return 1
	}
	return 0
}

// wireE2E builds the system on the harness's scratch tree and
// configuration. The seed's outbound_ssh_guard replaces the network dialer
// of the SSH client, so no browser case reaches the network.
func wireE2E(ctx context.Context, env e2eseed.Env) (*e2eseed.Backend, error) {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	var stopping atomic.Bool
	in := bootInput{lookup: env.Lookup, log: log, stopping: stopping.Load, fastHashing: env.FastHashing}
	if env.Dialer != nil {
		in.network = func(p *netpolicy.Policy) client.Network { return guardedNetwork{Policy: p, guard: env.Dialer} }
	}
	sys, err := openSystem(ctx, in)
	if err != nil {
		return nil, err
	}
	return &e2eseed.Backend{
		Stores: e2eStores{sys}.stores(),
		Hooks:  e2eseed.Hooks{OutputFlow: sys.terminal, FixtureSessions: sys.terminal},
		Serve: func(ctx context.Context, ln net.Listener, routes []protocol.Route) error {
			sys.realtime.Mount(routes...)
			srv := &http.Server{Handler: sys.handler(), ReadHeaderTimeout: 10 * time.Second, ErrorLog: slog.NewLogLogger(log.Handler(), slog.LevelWarn)}
			httpapi.ConfigureServer(srv)
			done := make(chan error, 1)
			go func() { done <- srv.Serve(ln) }()
			select {
			case err := <-done:
				return err
			case <-ctx.Done():
			}
			stopping.Store(true)
			sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			drainErr := sys.drain(sctx)
			err := srv.Shutdown(sctx)
			<-done
			return errors.Join(err, drainErr)
		},
		Close: sys.close,
	}, nil
}

// guardedNetwork refuses every outbound connection of the SSH client with
// the seed's text, while the destination checks stay those of the policy.
type guardedNetwork struct {
	*netpolicy.Policy
	guard *e2eseed.GuardDialer
}

func (g guardedNetwork) DialContext(ctx context.Context, role netpolicy.Role, network, addr string) (net.Conn, error) {
	return g.guard.DialContext(ctx, role, network, addr)
}

func (g guardedNetwork) DialRelay(ctx context.Context, role netpolicy.Role, network, addr string) (net.Conn, error) {
	return g.guard.DialContext(ctx, role, network, addr)
}

// e2eStores adapts the stores of the wired system to the seed applier.
// Nothing here is part of the release binary.
type e2eStores struct{ sys *system }

func (e e2eStores) stores() e2eseed.Stores {
	return e2eseed.Stores{
		Accounts: e, AppSettings: e.sys.settings, UserSettings: e.sys.settings,
		FeatureGates: e, Factors: e, Keys: e, Hosts: e, Identities: e,
	}
}

func (e e2eStores) LinkOIDC(ctx context.Context, userID int64, issuer, subject string) error {
	_, err := (&oidc.Links{DB: e.sys.db}).Link(ctx, userID, auth.Identity{Provider: auth.ProviderOIDC, Issuer: issuer, Subject: subject})
	return err
}

// LinkGitHub links a GitHub identity to a local account, as run_app.py
// adds a GitHubIdentity row: not provisioned, the account stays local.
func (e e2eStores) LinkGitHub(ctx context.Context, userID int64, githubUserID, login string) error {
	return e.sys.db.Write(ctx, func(tx *store.Tx) error {
		_, err := (&github.Service{DB: e.sys.db}).LinkTx(ctx, tx, userID,
			auth.Identity{Provider: auth.ProviderGitHub, Subject: githubUserID, Username: login})
		return err
	})
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
