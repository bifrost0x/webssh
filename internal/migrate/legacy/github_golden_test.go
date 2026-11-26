package legacy

import (
	"testing"

	"github.com/bifrost0x/webssh/internal/accounts"
	"github.com/bifrost0x/webssh/internal/auth"
	"github.com/bifrost0x/webssh/internal/auth/github"
	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/store"
)

// E04 and E06 against the golden data set: both GitHub identities map
// their numeric ids to the same accounts, the provisioned one stays
// GitHub-managed, and the client secret read back through
// internal/auth/github equals the manifest's value byte for byte.
func TestGoldenGitHubMigration(t *testing.T) {
	t.Parallel()
	dir := copyGolden(t)
	m := migrateM1(t, dir, golden.manifest.SecretKey.Value, M1{AdminUsers: []string{"cfg_admin"}})
	if e := m.entity(t, "E04"); e.Read != 2 || e.Written != 2 {
		t.Fatalf("E04 report %+v", e)
	}
	if e := m.entity(t, "E06"); e.Read != 1 || e.Written != 1 {
		t.Fatalf("E06 report %+v", e)
	}
	for _, p := range m.report.Pending {
		if p.Entity == "E04" || p.Entity == "E06" {
			t.Fatalf("%s still pending", p.Entity)
		}
	}
	svc := &github.Service{DB: m.db, Ring: m.ring}
	acc := &accounts.Service{DB: m.db}
	for _, c := range []struct {
		user, githubID string
		managed        accounts.Manager
	}{
		{"octo_golden", "90000001", accounts.ManagedGitHub},
		{"github_linked", "90000002", accounts.ManagedLocal},
	} {
		id, err := svc.Account(t.Context(), auth.Identity{Provider: auth.ProviderGitHub, Subject: c.githubID})
		want := goldenUserByName(t, c.user).ID
		if err != nil || id != want {
			t.Fatalf("%s: account %d, %v; want %d", c.user, id, err, want)
		}
		a, err := acc.Get(t.Context(), id)
		if err != nil || a.Managed != c.managed {
			t.Fatalf("%s: managed %q, %v", c.user, a.Managed, err)
		}
	}
	var cfg github.ImportedConfig
	err := m.db.Read(t.Context(), func(tx *store.Tx) error {
		var err error
		cfg, _, err = github.ImportedConfigTx(t.Context(), tx, m.ring)
		return err
	})
	if err != nil || string(cfg.ClientSecret) != golden.manifest.Values.GitHubClientSecret {
		t.Fatalf("client secret %q, %v", cfg.ClientSecret, err)
	}
	view, err := svc.Configuration(t.Context())
	if err != nil || view.Enabled || !view.SecretConfigured || view.RedirectURI == "" {
		t.Fatalf("configuration %+v, %v", view, err)
	}
}

// A GitHub client secret that does not decrypt stops the migration at
// E06; identities that are not unique stop it at E04; an identity of a
// missing account is reported and not taken over.
func TestGitHubMigrationNegative(t *testing.T) {
	t.Parallel()
	t.Run("secret does not decrypt", func(t *testing.T) {
		t.Parallel()
		dir := copyGolden(t)
		execLegacySQL(t, dir, `UPDATE github_auth_configuration SET encrypted_client_secret = CAST('gAAAAABtampered' AS BLOB)`)
		before := legacySnapshot(t, dir)
		_, err := startClosed(m1Options(t, dir, M1{}))
		assertStop(t, err, "E06")
		assertUntouched(t, dir, before)
		assertNoGoDatabase(t, dir)
	})
	t.Run("orphan identity", func(t *testing.T) {
		t.Parallel()
		dir := copyGolden(t)
		execLegacySQL(t, dir, `PRAGMA foreign_keys = OFF`, `INSERT INTO github_identities (user_id, github_user_id, login, provisioned_by_github, created_at, updated_at)
			VALUES (9999, '90000077', 'ghost', 0, '2026-11-02 09:00:00.000000', '2026-11-02 09:00:00.000000')`)
		m := migrateM1(t, dir, golden.manifest.SecretKey.Value, M1{})
		e := m.entity(t, "E04")
		if e.Read != 3 || e.Written != 2 || len(e.Flagged) != 1 || e.Flagged[0].Reason != "github_identity_without_account" {
			t.Fatalf("E04 report %+v", e)
		}
	})
}

// The client secret opens only in its own row binding: a sealed value
// copied to another column does not open.
func TestGitHubSecretBinding(t *testing.T) {
	t.Parallel()
	dir := copyGolden(t)
	m := migrateM1(t, dir, golden.manifest.SecretKey.Value, M1{})
	var sealed []byte
	if err := m.db.Read(t.Context(), func(tx *store.Tx) error {
		return tx.QueryRowContext(t.Context(), `SELECT client_secret FROM authgithub_config`).Scan(&sealed)
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.ring.Open(keyring.GitHubClientSecret, keyring.AAD{Table: "authgithub_config", Column: "client_secret", Row: "2"}, sealed); err == nil {
		t.Fatal("sealed secret opened under another row")
	}
}
