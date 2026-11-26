package legacy

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/store"
)

// tamperStep falsifies what its entity wrote, inside the staging
// transaction, so that the production verification must notice.
type tamperStep struct {
	Step
	target string
	tamper func(ctx context.Context, tx *store.Tx, seal Sealer) error
}

func (s *tamperStep) Write(ctx context.Context, tx *store.Tx, seal Sealer) error {
	if err := s.Step.Write(ctx, tx, seal); err != nil {
		return err
	}
	if s.Entity() != s.target {
		return nil
	}
	return s.tamper(ctx, tx, seal)
}

func execTx(stmts ...string) func(context.Context, *store.Tx, Sealer) error {
	return func(ctx context.Context, tx *store.Tx, _ Sealer) error {
		for _, q := range stmts {
			res, err := tx.ExecContext(ctx, q)
			if err != nil {
				return err
			}
			if n, _ := res.RowsAffected(); n == 0 {
				return errors.New("tamper changed nothing: " + q)
			}
		}
		return nil
	}
}

// reseal replaces a sealed value with change(plaintext), sealed under the
// same binding, so only a comparison of the content can notice.
func reseal(table, column, idColumn, where string, purpose keyring.Purpose, row func(id string) string,
	change func(ctx context.Context, tx *store.Tx, open Opener, plain []byte) ([]byte, error)) func(context.Context, *store.Tx, Sealer) error {
	return func(ctx context.Context, tx *store.Tx, seal Sealer) error {
		open := seal.(Opener)
		var id string
		var sealed []byte
		if err := tx.QueryRowContext(ctx, `SELECT CAST(`+idColumn+` AS TEXT), `+column+` FROM `+table+` WHERE `+where).Scan(&id, &sealed); err != nil {
			return err
		}
		ad := keyring.AAD{Table: table, Column: column, Row: row(id)}
		plain, err := open.Open(purpose, ad, sealed)
		if err != nil {
			return err
		}
		changed, err := change(ctx, tx, open, plain)
		if err != nil {
			return err
		}
		resealed, err := seal.Seal(purpose, ad, changed)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `UPDATE `+table+` SET `+column+` = ? WHERE CAST(`+idColumn+` AS TEXT) = ?`, resealed, id)
		return err
	}
}

func appendNewline(_ context.Context, _ *store.Tx, _ Opener, plain []byte) ([]byte, error) {
	return append(plain, '\n'), nil
}

// otherKey returns the plaintext of another key of user 3.
func otherKey(ctx context.Context, tx *store.Tx, open Opener, _ []byte) ([]byte, error) {
	var id string
	var sealed []byte
	if err := tx.QueryRowContext(ctx, `SELECT id, private_key FROM vault_ssh_keys WHERE user_id = 3 AND state = 'usable' ORDER BY seq DESC LIMIT 1`).Scan(&id, &sealed); err != nil {
		return nil, err
	}
	return open.Open(keyring.SSHKey, keyring.AAD{Table: "vault_ssh_keys", Column: "private_key", Row: "3:" + id}, sealed)
}

// The production verification notices a falsified record of every
// entity that writes: STOP with verify_failed naming the entity (or the
// entity whose verification covers the same rows first), nothing left.
func TestM1VerificationDetectsTampering(t *testing.T) {
	t.Parallel()
	usable := `user_id = 3 AND state = 'usable' AND seq = (SELECT min(seq) FROM vault_ssh_keys WHERE user_id = 3 AND state = 'usable')`
	tests := []struct {
		name, target, want string
		tamper             func(context.Context, *store.Tx, Sealer) error
	}{
		{"account name", "E01", "E01", execTx(`UPDATE accounts_users SET username = username || 'x' WHERE id = 3`)},
		{"account admin flag", "E01", "E01", execTx(`UPDATE accounts_users SET is_admin = 1 - is_admin WHERE id = 4`)},
		{"history generation", "A04", "E01", execTx(`UPDATE accounts_users SET history_generation = 'x' WHERE id = 3`)},
		{"password hash", "E02", "E02", execTx(`UPDATE authlocal_passwords SET hash = (SELECT hash FROM authlocal_passwords WHERE user_id = 4) WHERE user_id = 3`)},
		{"quarantine id", "E33", "E33", execTx(`UPDATE accounts_quarantine SET former_user_id = former_user_id + 1`)},
		{"feature gate", "E07", "E07", execTx(`UPDATE operations_feature_gates SET enabled = 1 - enabled WHERE feature = (SELECT min(feature) FROM operations_feature_gates)`)},
		{"TOTP label", "E08", "E08", execTx(`UPDATE totp_authenticators SET label = label || 'x'`)},
		{"TOTP replay step", "E08", "E08", execTx(`UPDATE totp_authenticators SET last_accepted_step = last_accepted_step - 1`)},
		{"TOTP secret", "E08", "E08", reseal("totp_authenticators", "sealed_secret", "id", "id = 1", keyring.TOTP,
			func(id string) string { return id + "/6" },
			func(context.Context, *store.Tx, Opener, []byte) ([]byte, error) { return []byte("JBSWY3DPEHPK3PXP"), nil })},
		{"passkey counter", "E10", "E10", execTx(`UPDATE webauthn_credentials SET sign_count = sign_count + 1 WHERE id = (SELECT min(id) FROM webauthn_credentials)`)},
		{"recovery code", "E11", "E11", execTx(`UPDATE auth_recovery_codes SET hash = zeroblob(32) WHERE id = (SELECT min(id) FROM auth_recovery_codes)`)},
		{"application setting", "E16", "E16", execTx(`UPDATE settings_app SET value = '"tampered"' WHERE key = (SELECT min(key) FROM settings_app WHERE source = 'migrated')`)},
		{"user setting", "E25", "E25", execTx(`UPDATE settings_user SET value = '"tampered"' WHERE user_id = 3 AND key = 'theme'`)},
		{"recovery notice", "A07", "A07", execTx(`UPDATE settings_app SET value = '{"restored_at":"2000-01-01T00:00:00+00:00"}' WHERE key = 'recovery_check'`)},
		{"key encoding", "E23", "E23", reseal("vault_ssh_keys", "private_key", "id", usable, keyring.SSHKey,
			func(id string) string { return "3:" + id }, appendNewline)},
		{"key swapped", "E23", "E23", reseal("vault_ssh_keys", "private_key", "id", usable, keyring.SSHKey,
			func(id string) string { return "3:" + id }, otherKey)},
		{"profile name", "E19", "E19", execTx(`UPDATE hosts_profiles SET "name" = '"tampered"' WHERE user_id = 3 AND position = 0`)},
		{"favourite", "A11", "E19", execTx(`UPDATE hosts_profiles SET "favorite" = 'true' WHERE user_id = 3 AND position = 0`)},
		{"jump host", "E20", "E20", execTx(`UPDATE hosts_jump_hosts SET "host" = '"tampered"' WHERE user_id = 3`)},
		{"SOCKS proxy", "E21", "E21", execTx(`UPDATE hosts_socks_proxies SET "remote_dns" = 'false' WHERE user_id = 3 AND position = 0`)},
		{"workspace preset", "A06", "A06", execTx(`UPDATE hosts_workspace_presets SET presets = '[]' WHERE user_id = 3`)},
		{"global known_hosts", "E17", "E17", execTx(`UPDATE hostkey_files SET raw = CAST(raw || char(10) AS BLOB) WHERE scope = 'global'`)},
		{"user known_hosts", "E24", "E24", execTx(`UPDATE hostkey_files SET raw = CAST(raw || char(10) AS BLOB) WHERE scope = 'user'`)},
		{"host note", "E28", "E28", execTx(`UPDATE hostops_notes SET body = body || 'x' WHERE profile_id IS NOT NULL`)},
		{"notepad", "A05", "A05", execTx(`UPDATE hostops_notes SET revision = revision + 1 WHERE profile_id IS NULL`)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := copyGolden(t)
			replaceIn(t, filepath.Join(dir, "users", "user_3", "settings.json"), `"notepad": ""`,
				`"notepad": "migrated notepad", "workspace_presets": [{"id": "p1", "name": "Main", "layout": 2, "profile_ids": []}]`)
			writeLegacyFile(t, dir, "recovery-check.json", `{"restored_at": "2026-11-02T10:00:40+00:00"}`)
			before := legacySnapshot(t, dir)
			m := M1{}
			m.wrap = func(s Step) Step { return &tamperStep{Step: s, target: tc.target, tamper: tc.tamper} }
			_, err := startClosed(m1Options(t, dir, m))
			se := assertStop(t, err, tc.want)
			if se.Code != CodeVerifyFailed {
				t.Fatalf("code %s: %v", se.Code, se)
			}
			assertUntouched(t, dir, before)
			assertNoGoDatabase(t, dir)
		})
	}
}

// A01 through the terminal store of the composition root.
func TestM1VerificationDetectsTamperedSession(t *testing.T) {
	t.Parallel()
	dir := extractLegacy(t, "datadir-extended.tar")
	m := M1{Persistent: &testPersistent{}}
	m.wrap = func(s Step) Step {
		return &tamperStep{Step: s, target: "A01", tamper: execTx(`UPDATE terminal_test_persistent SET tmux_session_name = tmux_session_name || 'x' WHERE row_id = (SELECT min(row_id) FROM terminal_test_persistent)`)}
	}
	o := m1Options(t, dir, m)
	o.Secret = legacyFixture(t).SecretKey.Value
	_, err := startClosed(o)
	if se := assertStop(t, err, "A01"); se.Code != CodeVerifyFailed {
		t.Fatalf("code %s", se.Code)
	}
}

