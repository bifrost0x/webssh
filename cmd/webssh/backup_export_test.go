package main

import (
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/backup"
	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/store"
)

// Every table of the build is classified for the portable export (OP1-5):
// remote authentication material (SSH private keys, saved passwords, the
// legacy automation vault) is scrubbed, as the Python export leaves out
// keys/, credentials.json and automation-vault.json; everything else is
// exported as Python exported it. A new table fails this test until it is
// classified, and a scrubbed table is empty in a real export.
func TestExportScrubsEveryRemoteCredential(t *testing.T) {
	scrubbed := []string{"vault_credential_assignments", "vault_credentials", "vault_credential_imports",
		"vault_legacy_automation", "vault_ssh_keys"}
	portable := []string{
		"accounts_id_floor", "accounts_quarantine", "accounts_users", "auth_factor_bootstrap", "auth_mfa_throttle",
		"auth_pending", "auth_recovery_codes", "authgithub_config", "authgithub_flights", "authgithub_identities",
		"authldap_identities", "authldap_revalidation", "authlocal_passwords", "authoidc_identities",
		"hostkey_files", "hostops_host_context", "hostops_notes", "hosts_jump_hosts", "hosts_profiles",
		"hosts_socks_proxies", "hosts_workspace_presets", "jobs_state", "migrate_keyring", "migrate_purge",
		"migrate_record", "operations_feature_gates", "session_epoch", "session_revocations", "session_sessions",
		"settings_app", "settings_notices", "settings_user", "smb_shares", "stepup_grants", "stepup_intents", "store_migrations",
		"terminal_persistent_sessions", "totp_authenticators", "totp_enrollments", "webauthn_challenges",
		"webauthn_credentials",
		// W3: runbooks and run history (the Python export carried
		// automation.json and automation-runs.json; step output is
		// redacted before it is stored), schedules (their approval binds
		// generations and digests, no secret) and the command library.
		"automation_runbook_steps", "automation_runbooks", "automation_runs", "automation_schedules",
		"commands_sets", "commands_user",
	}
	db, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "x.db"), store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.ApplyAll(t.Context(), schemas()...); err != nil {
		t.Fatal(err)
	}
	for _, name := range tableNames(t, db) {
		if !slices.Contains(scrubbed, name) && !slices.Contains(portable, name) {
			t.Errorf("table %s is not classified for the portable export", name)
		}
	}

	env := backupEnv(t)
	sys, _, _ := openEnv(t, env)
	if err := sys.db.Write(t.Context(), func(tx *store.Tx) error {
		_, err := tx.ExecContext(t.Context(), `INSERT INTO vault_ssh_keys VALUES ('k1', 1, 0, 'key', 'ed25519', '', '', x'00', '', 'usable')`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(t.TempDir(), "export.tar")
	_, material, err := keyring.MaterialLocation(sys.cfg.DataDir, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := backup.Export(t.Context(), backup.ExportRequest{Source: sys.db, Path: archive, Work: t.TempDir(), Scrub: exportScrubbers(),
		SecretKey: sys.cfg.SecretKey.Bytes(), Material: material, KeyID: sys.ring.KeyID(), Now: time.Now()}); err != nil {
		t.Fatal(err)
	}
	exported := filepath.Join(t.TempDir(), "export.db")
	if _, err := backup.VerifyWith(t.Context(), archive, backup.VerifyOptions{Secret: sys.cfg.SecretKey.Bytes(), Database: exported}); err != nil {
		t.Fatal(err)
	}
	edb, err := store.Open(t.Context(), exported, store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer edb.Close()
	for _, table := range scrubbed {
		if n := countRows(t, edb, `SELECT count(*) FROM `+table); n != 0 {
			t.Errorf("the export holds %d rows of %s", n, table)
		}
	}
}

func tableNames(t *testing.T, db *store.DB) []string {
	t.Helper()
	var tables []string
	err := db.Read(t.Context(), func(tx *store.Tx) error {
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
	return tables
}
