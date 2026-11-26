package legacy

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/bifrost0x/webssh/internal/accounts"
	"github.com/bifrost0x/webssh/internal/auth/local"
	"github.com/bifrost0x/webssh/internal/hostops"
	"github.com/bifrost0x/webssh/internal/principal/principaltest"
	"github.com/bifrost0x/webssh/internal/settings"
	"github.com/bifrost0x/webssh/internal/store"
	"github.com/bifrost0x/webssh/internal/vault"
)

func testProvider(t *testing.T, db *store.DB) *local.Provider {
	t.Helper()
	hasher, err := local.NewHasher(local.Params{Memory: 64, Time: 1, Threads: 1, KeyLen: 32, SaltLen: 16}, 2)
	if err != nil {
		t.Fatal(err)
	}
	return &local.Provider{DB: db, Accounts: &accounts.Service{DB: db}, Hasher: hasher}
}

func testVault(t *testing.T, m migrated) *vault.Service {
	t.Helper()
	v, err := vault.New(vault.Options{DB: m.db, Sealer: m.ring, StepUp: &principaltest.StepUp{},
		Limits: vault.Limits{MaxRecords: 100, MaxStoreBytes: 1 << 20}})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// Every DATA_DIR an older real release wrote migrates with the M1
// registry, its accounts sign in with their passwords, keys either sign
// with the public key of their plaintext or are kept as unsupported with
// a reason, and notepads arrive as notes.
func TestM1RealLegacyReleases(t *testing.T) {
	t.Parallel()
	fx := legacyFixture(t)
	for _, archive := range []string{"datadir-v1.0.0.tar", "datadir-2fcd38a.tar"} {
		t.Run(archive, func(t *testing.T) {
			t.Parallel()
			values := fx.Datadirs[archive].Values
			dir := extractLegacy(t, archive)
			m := migrateM1(t, dir, fx.SecretKey.Value, M1{Persistent: &testPersistent{}})
			provider := testProvider(t, m.db)
			var owner int64
			for name, u := range values.Users {
				if id, err := provider.Authenticate(t.Context(), name, u.Password); err != nil || id != u.ID {
					t.Errorf("%s signs in: %d, %v", name, id, err)
				}
				owner = max(owner, u.ID)
			}
			v := testVault(t, m)
			flagged := map[string]string{}
			for _, f := range m.entity(t, "E23").Flagged {
				flagged[f.ID] = f.Reason
				t.Logf("E23 flag %s: %s", f.ID, f.Reason)
			}
			for label, k := range values.Keys {
				plain, _ := base64.StdEncoding.DecodeString(k.PlaintextB64)
				keyOwner := keyOwnerOf(t, dir, k.Filename)
				signer, err := v.Signer(t.Context(), keyOwner, k.KeyID)
				want, parseErr := ssh.ParsePrivateKey(plain)
				switch {
				case parseErr == nil && k.KeyType != "DSA":
					if err != nil || !bytes.Equal(signer.PublicKey().Marshal(), want.PublicKey().Marshal()) {
						t.Errorf("%s: %v", label, err)
					}
				default:
					if err == nil {
						t.Errorf("%s: an unusable key signs", label)
					}
					if flagged[k.KeyID] == "" {
						t.Errorf("%s: not flagged as unsupported", label)
					}
				}
			}
			if values.Notepad != "" {
				var body string
				_ = m.db.Read(t.Context(), func(tx *store.Tx) error {
					for _, u := range values.Users {
						if b, _, found, _ := hostops.NoteTx(t.Context(), tx, u.ID, ""); found {
							body = b
						}
					}
					return nil
				})
				if body != values.Notepad {
					t.Errorf("notepad %q, want %q", body, values.Notepad)
				}
			}
			if m.entity(t, "E19").Written < len(values.Profiles) {
				t.Errorf("E19 wrote %d of %d profiles", m.entity(t, "E19").Written, len(values.Profiles))
			}
		})
	}
}

func keyOwnerOf(t *testing.T, dir, filename string) int64 {
	t.Helper()
	matches, _ := filepath.Glob(filepath.Join(dir, "users", "user_*", "keys", filename))
	if len(matches) != 1 {
		t.Fatalf("key file %s: %v", filename, matches)
	}
	var id int64
	if _, err := fmt.Sscanf(filepath.Base(filepath.Dir(filepath.Dir(matches[0]))), "user_%d", &id); err != nil {
		t.Fatal(err)
	}
	return id
}

// The 3.3.x data set with every boundary case of specification 8.2.
func TestM1ExtendedBoundaryCases(t *testing.T) {
	t.Parallel()
	fx := legacyFixture(t)
	ext := fx.Values.Extended
	dir := extractLegacy(t, "datadir-extended.tar")
	m := migrateM1(t, dir, fx.SecretKey.Value, M1{AdminUsers: []string{"cfg_admin"}, Persistent: &testPersistent{}})
	provider := testProvider(t, m.db)
	acc := &accounts.Service{DB: m.db}
	for name, c := range ext.CreatedAt {
		a, err := acc.Get(t.Context(), c.UserID)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		wantInc := ""
		if c.Incarnation != nil {
			wantInc = *c.Incarnation
		}
		if a.Incarnation != wantInc {
			t.Errorf("%s: incarnation %q, want %q", name, a.Incarnation, wantInc)
		}
		if id, err := provider.Authenticate(t.Context(), a.Username, c.Password); err != nil || id != c.UserID {
			t.Errorf("%s signs in: %v", name, err)
		}
	}
	nullUser := ext.CreatedAt["created_null"].UserID
	if !hasFlag(m.entity(t, "E01").Flagged, nullUser, "no_creation_time") {
		t.Errorf("created_at NULL not flagged: %+v", m.entity(t, "E01").Flagged)
	}
	v := testVault(t, m)
	for name, d := range ext.InterruptedKeyDeletions {
		_, err := v.Signer(t.Context(), 3, d.KeyID)
		if (d.RestoredFile != "") != (err == nil) {
			t.Errorf("interrupted deletion %s: %v", name, err)
		}
	}
	if !hasFlag(m.entity(t, "E17").Flagged, 0, "cert_authority_line") && !hasFlag(m.entity(t, "E24").Flagged, 3, "cert_authority_line") {
		t.Errorf("@cert-authority not flagged")
	}
	foundOrphan := false
	for _, k := range m.entity(t, "E28").KeptInPlace {
		foundOrphan = foundOrphan || strings.HasSuffix(k.Path, "host_context.json")
	}
	if !foundOrphan {
		t.Errorf("orphan host context not kept: %+v", m.entity(t, "E28"))
	}
	if e := m.entity(t, "A07"); e.Written != 1 {
		t.Errorf("recovery notice: %+v", e)
	}
	src := openLegacy(t, dir)
	check, err := src.RecoveryCheck()
	if err != nil || check.RestoredAt == "" {
		t.Fatalf("%+v, %v", check, err)
	}
	err = m.db.Read(t.Context(), func(tx *store.Tx) error {
		return settings.VerifyRecoveryCheck(t.Context(), tx, []byte(`{"restored_at":"`+check.RestoredAt+`"}`))
	})
	if err != nil {
		t.Error(err)
	}
	for _, p := range m.report.Pending {
		if p.Entity == "E37" && p.Count != 1 {
			t.Errorf("LDAP fence count %d", p.Count)
		}
	}
}

func hasFlag(flags []Flag, user int64, reason string) bool {
	for _, f := range flags {
		if f.UserID == user && strings.HasPrefix(f.Reason, reason) {
			return true
		}
	}
	return false
}

// Variants of specification 8.2 on top of the golden data set.
func TestM1Variants(t *testing.T) {
	t.Parallel()
	fx := legacyFixture(t)
	t.Run("admin_users_missing_account", func(t *testing.T) {
		t.Parallel()
		dir := copyGolden(t)
		m := migrateM1(t, dir, fx.SecretKey.Value, M1{AdminUsers: []string{"cfg_admin", "ghost_admin"}})
		w := m.entity(t, "E01").Warnings
		if len(w) != 1 || w[0].Code != "admin_user_missing" || !strings.Contains(w[0].Message, "ghost_admin") {
			t.Fatalf("%+v", w)
		}
	})
	t.Run("admin_users_promotes", func(t *testing.T) {
		t.Parallel()
		dir := copyGolden(t)
		m := migrateM1(t, dir, fx.SecretKey.Value, M1{AdminUsers: []string{"local_user", "locked_user", "ldap_user"}})
		a, _ := (&accounts.Service{DB: m.db}).Get(t.Context(), goldenUserByName(t, "local_user").ID)
		locked, _ := (&accounts.Service{DB: m.db}).Get(t.Context(), goldenUserByName(t, "locked_user").ID)
		ldap, _ := (&accounts.Service{DB: m.db}).Get(t.Context(), goldenUserByName(t, "ldap_user").ID)
		if !a.IsAdmin || locked.IsAdmin || ldap.IsAdmin || ldap.Managed != accounts.ManagedLDAP {
			t.Fatalf("local %v, locked %v, ldap %v (%s)", a.IsAdmin, locked.IsAdmin, ldap.IsAdmin, ldap.Managed)
		}
		if w := m.entity(t, "E01").Warnings; len(w) != 1 || w[0].Code != "admin_promoted_at_migration" {
			t.Fatalf("%+v", w)
		}
	})
	for _, name := range []string{"app_settings_schema_1", "recovery_check_malformed", "recovery_check_oversized"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dir := copyGolden(t)
			for rel, b64 := range fx.Variants[name].Files {
				content, _ := base64.StdEncoding.DecodeString(b64)
				writeLegacyFile(t, dir, strings.TrimPrefix(rel, "data/"), string(content))
			}
			m := migrateM1(t, dir, fx.SecretKey.Value, M1{})
			if strings.HasPrefix(name, "recovery_check") {
				if e := m.entity(t, "A07"); len(e.Flagged) != 1 || e.Written != 0 {
					t.Fatalf("%+v", e)
				}
			}
		})
	}
	t.Run("database_trigger_and_view", func(t *testing.T) {
		t.Parallel()
		dir := copyGolden(t)
		execLegacySQL(t, dir, fx.Variants["database_trigger_and_view"].SQL...)
		migrateM1(t, dir, fx.SecretKey.Value, M1{})
	})
}
