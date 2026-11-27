package main

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/bifrost0x/webssh/internal/auth/github"
	"github.com/bifrost0x/webssh/internal/auth/totp"
	"github.com/bifrost0x/webssh/internal/backup"
	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/migrate/legacy"
	"github.com/bifrost0x/webssh/internal/store"
	"github.com/bifrost0x/webssh/internal/vault"
)

// rotationEnv points the commands at dir with SECRET_KEY taken from
// DATA_DIR/secret_key, as the entrypoint does when the environment has
// none. The tests using it must not run in parallel.
func rotationEnv(t *testing.T, dir string) {
	t.Helper()
	t.Setenv("DATA_DIR", dir)
	t.Setenv("BACKUP_TEMP_DIR", t.TempDir())
	t.Setenv("SECRET_KEY", "")
	if err := os.Unsetenv("SECRET_KEY"); err != nil {
		t.Fatal(err)
	}
}

// migratedPurged returns the extended golden data set migrated by Go and
// purged of the legacy data with `webssh legacy purge`: the state in
// which a rotation is allowed.
func migratedPurged(t *testing.T) string {
	t.Helper()
	dir := extractGolden(t, "datadir-extended.tar")
	rotationEnv(t, dir)
	if out := runCLI(t, "migrate", "--dry-run"); out.Code != 0 {
		t.Fatalf("dry run: %+v", out)
	}
	g, err := openCommandDataMigrating(t)
	if err != nil {
		t.Fatal(err)
	}
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	if out := runCLI(t, "rotate-secret-key", "--confirm-offline"); out.Code != 1 ||
		!strings.Contains(out.Stderr, "cannot be rotated while legacy data exists") {
		t.Fatalf("rotation beside legacy data: %+v", out)
	}
	purgeLegacy(t, dir)
	return dir
}

// purgeLegacy runs `webssh legacy purge` with a backup: the state in
// which a rotation is allowed (OP2-1, every entity of the golden data set
// is migrated since the third wave).
func purgeLegacy(t *testing.T, dir string) {
	t.Helper()
	out := runCLI(t, "legacy", "purge", "--yes", "--backup-to", t.TempDir())
	if out.Code != 0 {
		t.Fatalf("legacy purge: %+v", out)
	}
	if _, err := os.Lstat(filepath.Join(dir, "app.db")); !os.IsNotExist(err) {
		t.Fatalf("the purge left app.db: %v", err)
	}
}

// openCommandDataMigrating migrates the legacy data the way a server
// start does.
func openCommandDataMigrating(t *testing.T) (*goData, error) {
	t.Helper()
	cfg, err := loadConfig()
	if err != nil {
		return nil, err
	}
	st, err := startMigration(t.Context(), cfg, os.LookupEnv, slog.New(slog.DiscardHandler))
	if err != nil {
		return nil, err
	}
	if !st.Migrated {
		t.Fatalf("state %s, not migrated", st.State)
	}
	return &goData{startup: st}, nil
}

type cliOut struct {
	Code           int
	Stdout, Stderr string
}

func runCLI(t *testing.T, args ...string) cliOut {
	t.Helper()
	var out, errOut bytes.Buffer
	code := dispatch(t.Context(), append([]string{"/app/webssh"}, args...), streams{stdin: strings.NewReader(""), stdout: &out, stderr: &errOut})
	return cliOut{code, out.String(), errOut.String()}
}

// secrets opens every sealed secret of the data directory with the
// configuration as the next start reads it, and checks the key
// identifier like a start does.
func secrets(t *testing.T) map[string]string {
	t.Helper()
	cfg, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	g, err := openGoData(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	stored, err := legacy.StoredKeyID(t.Context(), g.db)
	if err != nil || g.ring.Verify(stored) != nil {
		t.Fatalf("key identifier %q does not match the ring %s: %v", stored, g.ring, err)
	}
	out := map[string]string{}
	err = g.db.Read(t.Context(), func(tx *store.Tx) error {
		users, err := int64s(t.Context(), tx, `SELECT user_id FROM vault_ssh_keys UNION SELECT user_id FROM vault_credentials ORDER BY 1`)
		if err != nil {
			return err
		}
		for _, u := range users {
			keys, err := vault.ExportKeysTx(t.Context(), tx, g.ring, u)
			if err != nil {
				return err
			}
			for _, k := range keys {
				out[fmt.Sprintf("key %d %s", u, k.ID)] = string(k.PEM)
			}
			creds, _, _, err := vault.ExportCredentialsTx(t.Context(), tx, g.ring, u)
			if err != nil {
				return err
			}
			for _, c := range creds {
				out[fmt.Sprintf("credential %d %s", u, c.ID)] = string(c.Password)
			}
		}
		ids, err := int64s(t.Context(), tx, `SELECT id FROM totp_authenticators ORDER BY id`)
		if err != nil {
			return err
		}
		ts := &totp.Service{DB: g.db, Ring: g.ring}
		for _, id := range ids {
			a, err := ts.ExportTx(t.Context(), tx, id)
			if err != nil {
				return err
			}
			out[fmt.Sprintf("totp %d", id)] = a.Base32
		}
		c, ok, err := github.ImportedConfigTx(t.Context(), tx, g.ring)
		if err != nil {
			return err
		}
		if ok && c.ClientSecret != nil {
			out["github"] = string(c.ClientSecret)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func int64s(ctx context.Context, tx *store.Tx, q string) ([]int64, error) {
	rows, err := tx.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var v int64
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func count(t *testing.T, dir, q string) int {
	t.Helper()
	db, err := store.Open(t.Context(), filepath.Join(dir, keyring.GoDirName, keyring.DatabaseName), store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var n int
	if err := db.Read(t.Context(), func(tx *store.Tx) error { return tx.QueryRowContext(t.Context(), q).Scan(&n) }); err != nil {
		t.Fatal(err)
	}
	return n
}

func readSecret(t *testing.T, dir string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "secret_key"))
	if err != nil {
		t.Fatal(err)
	}
	return string(trimSecret(raw))
}

// After the purge, rotate-secret-key reseals every secret of the golden
// data set under a new SECRET_KEY: every one opens to the same plaintext
// afterwards, the old key no longer opens the database, the sessions are
// gone, and the backup written before verifies with the old key.
func TestRotateSecretKeyGolden(t *testing.T) {
	dir := migratedPurged(t)
	before := secrets(t)
	if len(before) < 5 || before["github"] == "" {
		t.Fatalf("the golden data set yields too few secrets: %v", slices.Sorted(maps.Keys(before)))
	}
	oldSecret := readSecret(t, dir)
	out := runCLI(t, "rotate-secret-key", "--confirm-offline")
	if out.Code != 0 {
		t.Fatalf("rotation: %+v", out)
	}
	keys, creds := 0, 0
	for k := range before {
		switch {
		case strings.HasPrefix(k, "key "):
			keys++
		case strings.HasPrefix(k, "credential "):
			creds++
		}
	}
	totps := len(before) - keys - creds - 1
	prefix := fmt.Sprintf("SECRET_KEY rotated for %d stored SSH keys and %d TOTP secrets and 1 GitHub client secrets and %d named credentials. Verified private recovery snapshot: ",
		keys, totps, creds)
	lines := strings.Split(strings.TrimSuffix(out.Stdout, "\n"), "\n")
	if len(lines) != 2 || !strings.HasPrefix(lines[0], prefix) ||
		lines[1] != "Restart WebSSH now so every process loads the new persisted secret." {
		t.Fatalf("output %q, want prefix %q", out.Stdout, prefix)
	}
	t.Logf("%s", lines[0])
	backupPath := strings.TrimPrefix(lines[0], prefix)
	newSecret := readSecret(t, dir)
	if newSecret == oldSecret || len(newSecret) != 64 {
		t.Fatalf("secret %q after rotation", newSecret)
	}
	if after := secrets(t); !maps.Equal(after, before) {
		t.Fatalf("secrets differ after the rotation")
	}
	if n := count(t, dir, `SELECT count(*) FROM session_sessions`); n != 0 {
		t.Fatalf("%d sessions survived the rotation", n)
	}
	v, err := backup.Verify(t.Context(), backupPath, vault.ProbeSealed, totp.ProbeSealed)
	if err != nil {
		t.Fatalf("pre-rotation backup: %v", err)
	}
	material, err := keyring.LoadOrCreateMaterial(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	oldRing, err := keyring.Open([]byte(oldSecret), material)
	if err != nil {
		t.Fatal(err)
	}
	if v.Manifest.KeyID != oldRing.KeyID() {
		t.Fatalf("backup key %s, old ring %s", v.Manifest.KeyID, oldRing.KeyID())
	}
	if _, err := os.Lstat(filepath.Join(dir, keyring.GoDirName, backup.PendingSecretName)); !os.IsNotExist(err) {
		t.Fatalf("pending secret left behind: %v", err)
	}
	// A second rotation works from the new key.
	if out := runCLI(t, "rotate-secret-key", "--confirm-offline"); out.Code != 0 {
		t.Fatalf("second rotation: %+v", out)
	}
	if after := secrets(t); !maps.Equal(after, before) {
		t.Fatalf("secrets differ after the second rotation")
	}
}

func TestRotateSecretKeyRefusals(t *testing.T) {
	dir := migratedPurged(t)
	before := readSecret(t, dir)
	if out := runCLI(t, "rotate-secret-key"); out.Code != 1 || !strings.Contains(out.Stderr, "--confirm-offline") {
		t.Fatalf("without --confirm-offline: %+v", out)
	}
	// A running server holds the Go lock.
	cfg, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	o, err := migrationOptions(cfg, os.LookupEnv)
	if err != nil {
		t.Fatal(err)
	}
	st, err := legacy.Start(t.Context(), o)
	if err != nil {
		t.Fatal(err)
	}
	out := runCLI(t, "rotate-secret-key", "--confirm-offline")
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	if out.Code != 1 || !strings.Contains(out.Stderr, "WebSSH is running on this data directory") {
		t.Fatalf("beside a running server: %+v", out)
	}
	t.Setenv("SECRET_KEY", before)
	if out := runCLI(t, "rotate-secret-key", "--confirm-offline"); out.Code != 1 ||
		!strings.Contains(out.Stderr, "SECRET_KEY is set in the environment") {
		t.Fatalf("secret from the environment: %+v", out)
	}
	if got := readSecret(t, dir); got != before {
		t.Fatal("a refused rotation changed the secret")
	}
}

// Every table of this build is either handled by a rotation step or holds
// nothing the keyring sealed or MACed. A new table must be classified
// here; one with a sealed column that no step handles stops the rotation
// anyway (backup.ErrRotationLeftover), but MAC tables cannot be detected.
func TestRotationCoversEveryTable(t *testing.T) {
	handled := map[string]string{
		"vault_ssh_keys": stepSSHKeys, "vault_credentials": stepCredentials, "totp_authenticators": stepTOTP,
		"totp_enrollments": stepTOTP, "authgithub_config": stepGitHub, "authgithub_flights": stepGitHub,
		"session_sessions": "sessions", "stepup_grants": "step_up", "stepup_intents": "step_up",
		"auth_pending": "pending_sign_ins", "auth_factor_bootstrap": "pending_sign_ins",
		"webauthn_challenges": "passkey_challenges",
	}
	without := []string{
		"accounts_id_floor", "accounts_quarantine", "accounts_users", "auth_mfa_throttle",
		"auth_recovery_codes", // SHA-256 without a key
		"authgithub_identities", "authldap_identities", "authldap_revalidation", "authlocal_passwords",
		"authoidc_identities", "hostkey_files", "hostops_host_context", "hostops_notes", "hosts_jump_hosts",
		"hosts_profiles", "hosts_socks_proxies", "hosts_workspace_presets", "jobs_state", "migrate_keyring",
		"migrate_purge", "migrate_record", "operations_feature_gates", "session_epoch", "session_revocations",
		"settings_app", "settings_user", "smb_shares", "store_migrations", "terminal_persistent_sessions",
		"vault_credential_assignments", "vault_credential_imports",
		"vault_legacy_automation", // sealed with the user's passphrase, not the keyring
		"webauthn_credentials",
		// W3: runbooks, runs (output redacted before it is stored),
		// schedules (bindings are generations and unkeyed digests, the
		// metadata tokens of the permission jobs use a key in memory),
		// the command library. Transfer tokens and backup operations
		// live in memory only.
		"automation_runbook_steps", "automation_runbooks", "automation_runs", "automation_schedules",
		"commands_sets", "commands_user",
	}
	steps := map[string]bool{}
	for _, s := range rotationSteps() {
		steps[s.Name] = true
	}
	db, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "x.db"), store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.ApplyAll(t.Context(), schemas()...); err != nil {
		t.Fatal(err)
	}
	var tables []string
	err = db.Read(t.Context(), func(tx *store.Tx) error {
		rows, err := tx.QueryContext(t.Context(), `SELECT name FROM sqlite_schema WHERE type = 'table' ORDER BY name`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var n string
			if err := rows.Scan(&n); err != nil {
				return err
			}
			tables = append(tables, n)
		}
		return rows.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range tables {
		step, ok := handled[name]
		switch {
		case ok && !steps[step]:
			t.Errorf("table %s: step %q is not in rotationSteps", name, step)
		case !ok && !slices.Contains(without, name):
			t.Errorf("table %s is not classified for the secret rotation", name)
		}
	}
	for name := range handled {
		if !slices.Contains(tables, name) {
			t.Errorf("classified table %s does not exist", name)
		}
	}
}
