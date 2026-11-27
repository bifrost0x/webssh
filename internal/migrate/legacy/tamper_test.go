package legacy

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bifrost0x/webssh/internal/principal/principaltest"
)

// Spec 8.3 (RS4-02): one flipped bit per Fernet token and per GCM
// ciphertext and tag is a STOP for a damaged record naming entity, user
// and record; it must not read as a wrong SECRET_KEY when other records
// decrypt with the same key.
func TestFlippedTOTPOfSecondUserNamesUser(t *testing.T) {
	t.Parallel()
	dir := copyGolden(t)
	// user 6 keeps its valid secret; user 3 gets a copy with one changed
	// base64 character.
	execLegacySQL(t, dir, `INSERT INTO totp_authenticators (id, user_id, encrypted_secret, label, active, created_at)
		SELECT 2, 3, substr(encrypted_secret, 1, 40) || CASE substr(encrypted_secret, 41, 1) WHEN 'A' THEN 'B' ELSE 'A' END || substr(encrypted_secret, 42),
		'x', 1, created_at FROM totp_authenticators WHERE id = 1`)
	before := legacySnapshot(t, dir)
	_, err := startClosed(m1Options(t, dir, M1{}))
	se := assertStop(t, err, "E08")
	assertUntouched(t, dir, before)
	assertNoGoDatabase(t, dir)
	if se.Code != CodeRecordDamaged || se.Record != "totp_authenticators 2" {
		t.Errorf("a single tampered TOTP record is not reported as a damaged record: %v", se)
	}
	if se.UserID != 3 {
		t.Errorf("STOP names user %d, want 3: %v", se.UserID, se)
	}
}

func TestFlippedGCMTagNamesCredential(t *testing.T) {
	t.Parallel()
	for _, where := range []string{"ciphertext", "tag"} {
		t.Run(where, func(t *testing.T) {
			t.Parallel()
			dir := copyGolden(t)
			p := filepath.Join(dir, "users", "user_3", "credentials.json")
			raw, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			var doc map[string]any
			if err := json.Unmarshal(raw, &doc); err != nil {
				t.Fatal(err)
			}
			c := doc["credentials"].(map[string]any)["4e37638ac61ccce2da594b17f59ac9e6"].(map[string]any)
			ct, err := base64.StdEncoding.DecodeString(c["ciphertext"].(string))
			if err != nil {
				t.Fatal(err)
			}
			if where == "tag" {
				ct[len(ct)-1] ^= 1
			} else {
				ct[13] ^= 1
			}
			c["ciphertext"] = base64.StdEncoding.EncodeToString(ct)
			out, _ := json.Marshal(doc)
			if err := os.WriteFile(p, out, 0o600); err != nil {
				t.Fatal(err)
			}
			before := legacySnapshot(t, dir)
			o := m1Options(t, dir, M1{})
			o.Registry = restoreRegistry(t)
			_, err = startClosed(o)
			se := assertStop(t, err, "E32")
			assertUntouched(t, dir, before)
			assertNoGoDatabase(t, dir)
			if se.Code != CodeRecordDamaged || se.UserID != 3 {
				t.Errorf("STOP %+v, want a tampered record of user 3", se)
			}
			t.Logf("STOP: %v (user %d)", se, se.UserID)
		})
	}
}

// Spec 8.3: duplicate credential ids are STOP naming user and file.
func TestDuplicateCredentialIDsStop(t *testing.T) {
	t.Parallel()
	for name, change := range map[string]func(string) string{
		"duplicate member": func(s string) string {
			return strings.Replace(s, `"credentials": {`, `"credentials": {"90efb144e688fdb2f30a50a01b2e6ff4": {"id": "x"}, `, 1)
		},
		"id differs from member": func(s string) string {
			return strings.Replace(s, `"id": "90efb144e688fdb2f30a50a01b2e6ff4"`, `"id": "4e37638ac61ccce2da594b17f59ac9e6"`, 1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dir := copyGolden(t)
			p := filepath.Join(dir, "users", "user_3", "credentials.json")
			raw, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			changed := change(string(raw))
			if changed == string(raw) {
				t.Fatal("no change")
			}
			if err := os.WriteFile(p, []byte(changed), 0o600); err != nil {
				t.Fatal(err)
			}
			o := m1Options(t, dir, M1{})
			o.Registry = restoreRegistry(t)
			_, err = startClosed(o)
			se := assertStop(t, err, "E32")
			assertNoGoDatabase(t, dir)
			t.Logf("STOP: %v", se)
		})
	}
}

// A writer that changes a per-user store between the read of all
// accounts and the account-by-account write (MG1-1) is caught by the
// digest re-check, also when the new content is valid.
func TestChangeBetweenAccountReadAndWrite(t *testing.T) {
	t.Parallel()
	for _, point := range []string{PointRead, PointStaged} {
		t.Run(point, func(t *testing.T) {
			t.Parallel()
			dir := copyGolden(t)
			o := m1Options(t, dir, M1{})
			o.Registry = restoreRegistry(t)
			o.checkpoint = func(p string) {
				if p == point {
					path := filepath.Join(dir, "users", "user_3", "credentials.json")
					data, _ := os.ReadFile(path)
					_ = os.WriteFile(path, []byte(strings.Replace(string(data), "Golden saved password", "Golden saved passwort", 1)), 0o600)
				}
			}
			_, err := startClosed(o)
			if stopCode(err) != CodeChangedDuring {
				t.Fatalf("err = %v", err)
			}
			assertNoGoDatabase(t, dir)
		})
	}
}

// Spec 8.3: a tampered vault ciphertext passes the structural check and
// fails at import, leaving the passwords unchanged.
func TestTamperedVaultFailsAtImport(t *testing.T) {
	t.Parallel()
	dir := copyGolden(t)
	p := filepath.Join(dir, "users", "user_3", "automation-vault.json")
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	ct, _ := base64.StdEncoding.DecodeString(doc["ciphertext"].(string))
	ct[len(ct)-1] ^= 1
	doc["ciphertext"] = base64.StdEncoding.EncodeToString(ct)
	out, _ := json.Marshal(doc)
	if err := os.WriteFile(p, out, 0o600); err != nil {
		t.Fatal(err)
	}
	_, svc, steps := migrateCredentials(t, dir, golden.manifest.SecretKey.Value)
	owner := goldenUserByName(t, "local_user").ID
	pr := principaltest.User(owner)
	if err := importLegacy(t, svc, steps, pr, golden.manifest.Values.VaultPassphrase); err == nil {
		t.Fatal("a tampered vault imported")
	} else {
		t.Logf("import: %v", err)
	}
	if names, _, waiting := credentialState(t, svc, pr); len(names) != 2 || !waiting {
		t.Fatalf("a failed import changed the state: %v %v", names, waiting)
	}
}
