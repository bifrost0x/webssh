package legacy

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Specification 8.3, for the entities of M1: manipulated legacy data is
// STOP naming the entity (and the user where there is one), nothing is
// written, and the legacy data stays unchanged.
func TestM1NegativeCases(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		entity string
		change func(t *testing.T, dir string)
	}{
		{"flipped bit in a Fernet key file", "E23", func(t *testing.T, dir string) {
			p := filepath.Join(dir, "users", "user_3", "keys", "9971eb1e-92db-4b73-93dd-b5c5d5d8387c.pem")
			flipBase64(t, p)
		}},
		{"key file listed but missing", "E23", func(t *testing.T, dir string) {
			if err := os.Remove(filepath.Join(dir, "users", "user_3", "keys", "168716ca-55b4-4155-8827-f5d378fe0ad0.pem")); err != nil {
				t.Fatal(err)
			}
		}},
		{"key file name with ..", "E23", func(t *testing.T, dir string) {
			replaceIn(t, filepath.Join(dir, "users", "user_3", "keys", "keys.json"),
				`"filename": "168716ca-55b4-4155-8827-f5d378fe0ad0.pem"`, `"filename": "../168716ca.pem"`)
		}},
		{"duplicate key ids", "E23", func(t *testing.T, dir string) {
			replaceIn(t, filepath.Join(dir, "users", "user_3", "keys", "keys.json"),
				`"id": "168716ca-55b4-4155-8827-f5d378fe0ad0"`, `"id": "9971eb1e-92db-4b73-93dd-b5c5d5d8387c"`)
		}},
		{"invalid known_hosts line", "E17", func(t *testing.T, dir string) {
			appendTo(t, filepath.Join(dir, "known_hosts"), "broken-line-without-key\n")
		}},
		{"invalid user known_hosts line", "E24", func(t *testing.T, dir string) {
			appendTo(t, filepath.Join(dir, "users", "user_3", "known_hosts"), "host ssh-ed25519 !!!\n")
		}},
		{"future profiles schema", "E19", func(t *testing.T, dir string) {
			replaceIn(t, filepath.Join(dir, "users", "user_3", "profiles.json"), `"schema_version": 3`, `"schema_version": 4`)
		}},
		{"profile Python's validator refuses", "E19", func(t *testing.T, dir string) {
			replaceIn(t, filepath.Join(dir, "users", "user_3", "profiles.json"), `"port": 22`, `"port": "twenty-two"`)
		}},
		{"future settings schema", "E25", func(t *testing.T, dir string) {
			replaceIn(t, filepath.Join(dir, "users", "user_3", "settings.json"), `"schema_version": 2`, `"schema_version": 3`)
		}},
		{"malformed session_epoch", "E18", func(t *testing.T, dir string) {
			writeLegacyFile(t, dir, "session_epoch", "not-an-epoch\n")
		}},
		{"unknown security feature", "E07", func(t *testing.T, dir string) {
			execLegacySQL(t, dir, `INSERT INTO security_feature_states (feature, enabled, updated_at) VALUES ('magic', 1, '2026-11-02 09:00:00')`)
		}},
		{"password hash that is not bcrypt", "E02", func(t *testing.T, dir string) {
			execLegacySQL(t, dir, `UPDATE users SET password_hash = 'plain-text' WHERE id = 4`)
		}},
		{"recovery code hash of the wrong length", "E11", func(t *testing.T, dir string) {
			execLegacySQL(t, dir, `UPDATE recovery_codes SET code_hash = X'00' WHERE id = (SELECT min(id) FROM recovery_codes)`)
		}},
		{"flipped bit in the TOTP secret", "E08", func(t *testing.T, dir string) {
			execLegacySQL(t, dir, `UPDATE totp_authenticators SET encrypted_secret = substr(encrypted_secret, 1, 40) || 'A' || substr(encrypted_secret, 42)`)
		}},
		{"invalid host context", "E28", func(t *testing.T, dir string) {
			writeLegacyFile(t, dir, "users/user_3/host_context.json", `{"version": 1, "hosts": {"x": {"revision": 0, "notes": "", "directories": [], "command_sets": []}}}`)
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := copyGolden(t)
			tc.change(t, dir)
			before := legacySnapshot(t, dir)
			_, err := startClosed(m1Options(t, dir, M1{}))
			se, ok := stopOf(err)
			if !ok {
				t.Fatalf("no STOP: %v", err)
			}
			if se.Entity != tc.entity && se.Code != CodeSecretMismatch {
				t.Fatalf("STOP %v, want entity %s", se, tc.entity)
			}
			assertUntouched(t, dir, before)
			assertNoGoDatabase(t, dir)
		})
	}
}

func stopOf(err error) (*StopError, bool) {
	return errors.AsType[*StopError](err)
}

func flipBase64(t *testing.T, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.URLEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	raw[40] ^= 1
	if err := os.WriteFile(path, []byte(base64.URLEncoding.EncodeToString(raw)), 0o600); err != nil {
		t.Fatal(err)
	}
}

func replaceIn(t *testing.T, path, old, repl string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), old) {
		t.Fatalf("%s does not contain %q", path, old)
	}
	if err := os.WriteFile(path, []byte(strings.Replace(string(data), old, repl, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
}

func appendTo(t *testing.T, path, text string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(text); err != nil {
		t.Fatal(err)
	}
}

// Keys this release cannot sign with are migrated sealed as unsupported
// and named with the reason (condition W2-Int, specification 4.8): an
// RSA key below 1024 bits; the other keys stay usable.
func TestM1WeakRSAKeyIsUnsupported(t *testing.T) {
	t.Parallel()
	dir := copyGolden(t)
	weak := weakRSAKey(t)
	const id = "0f0f0f0f-0000-4000-8000-000000000512"
	writeLegacyFile(t, dir, "users/user_3/keys/"+id+".pem", string(weak))
	replaceIn(t, filepath.Join(dir, "users", "user_3", "keys", "keys.json"), `"keys": [`,
		`"keys": [{"id": "`+id+`", "name": "weak-512", "filename": "`+id+`.pem", "key_type": "RSA", "encrypted": false, "uploaded_at": "2020-01-01T00:00:00"},`)
	m := migrateM1(t, dir, golden.manifest.SecretKey.Value, M1{})
	if !hasFlag(m.entity(t, "E23").Flagged, 3, "unsupported: RSA key with 512 bits") {
		t.Fatalf("%+v", m.entity(t, "E23").Flagged)
	}
	v := testVault(t, m)
	if _, err := v.Signer(t.Context(), 3, id); err == nil {
		t.Fatal("the 512-bit key signs")
	}
	if _, err := v.Signer(t.Context(), 3, "9971eb1e-92db-4b73-93dd-b5c5d5d8387c"); err != nil {
		t.Fatalf("a usable key: %v", err)
	}
}

// A user directory without an account and an unrecognised entry below
// deleted_users/ stay in place and are reported; neither stops.
func TestM1OrphansStayInPlace(t *testing.T) {
	t.Parallel()
	dir := copyGolden(t)
	writeLegacyFile(t, dir, "users/user_99/settings.json", `{"schema_version": 2}`)
	writeLegacyFile(t, dir, "deleted_users/notes/readme.txt", "operator note")
	m := migrateM1(t, dir, golden.manifest.SecretKey.Value, M1{})
	kept := map[string]string{}
	for _, e := range []string{"E01", "E33"} {
		for _, k := range m.entity(t, e).KeptInPlace {
			kept[k.Path] = k.Reason
		}
	}
	if kept["users/user_99"] != "user_directory_without_account" || kept["deleted_users/notes"] != "unrecognised_entry" {
		t.Fatalf("%v", kept)
	}
}

// weakRSAKey builds a 512-bit RSA key in PKCS#1 PEM form from fixed,
// synthetic primes; crypto/rsa no longer generates such keys.
func weakRSAKey(t *testing.T) []byte {
	t.Helper()
	p, _ := new(big.Int).SetString("f067a84fe77c2367f4fb2276b793822e3f19ce78f6e933a8087eef6629ff5599", 16)
	q, _ := new(big.Int).SetString("c2c287d09e1bac57708b5f6901a7620ae117cab9c20d86a4369badfd3f85e327", 16)
	one := big.NewInt(1)
	phi := new(big.Int).Mul(new(big.Int).Sub(p, one), new(big.Int).Sub(q, one))
	key := &rsa.PrivateKey{PublicKey: rsa.PublicKey{N: new(big.Int).Mul(p, q), E: 65537}, Primes: []*big.Int{p, q}}
	key.D = new(big.Int).ModInverse(big.NewInt(65537), phi)
	key.Precompute()
	if key.N.BitLen() != 512 {
		t.Fatalf("modulus has %d bits", key.N.BitLen())
	}
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
}
