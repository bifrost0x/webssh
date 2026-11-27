package legacy

import (
	"encoding/json/jsontext"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bifrost0x/webssh/internal/files/smb"
	"github.com/bifrost0x/webssh/internal/pyjson"
	"github.com/bifrost0x/webssh/internal/store"
)

func smbM1Registry(t *testing.T, m M1) *Registry {
	t.Helper()
	r := m1Registry(t, m)
	if err := AddSMB(r); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestAddSMBTakesOverThePendingEntity(t *testing.T) {
	t.Parallel()
	r := smbM1Registry(t, M1{})
	for _, c := range r.coverage() {
		if c.Entity == "E22" && c.Kind != CoverStep {
			t.Errorf("E22 is %s", c.Kind)
		}
	}
	if len(r.Uncovered()) != 0 {
		t.Fatalf("uncovered %v", r.Uncovered())
	}
	if err := AddSMB(r); err == nil {
		t.Fatal("registering the step twice must fail")
	}
}

func migrateWithSMB(t *testing.T, dataDir, secret string) migrated {
	t.Helper()
	before := legacySnapshot(t, dataDir)
	o := testOptions(t, dataDir)
	o.Registry = smbM1Registry(t, M1{AdminUsers: []string{"cfg_admin"}, Persistent: &testPersistent{}})
	o.Secret = secret
	st, err := startClosed(o)
	if err != nil || !st.Migrated {
		t.Fatalf("migration: %+v, %v", st, err)
	}
	assertUntouched(t, dataDir, before)
	return openMigrated(t, dataDir, secret, st.Report)
}

// E22: both golden definitions of user 3 arrive verbatim, in order, the
// empty domain kept empty and the Unicode name byte for byte; the store
// serves them and a saved definition can be changed after the migration.
func TestSMBGoldenShares(t *testing.T) {
	dir := copyGolden(t)
	raw, err := os.ReadFile(filepath.Join(dir, "users", "user_3", "smb_shares.json"))
	if err != nil {
		t.Fatal(err)
	}
	doc, _, err := pyjson.Load(raw)
	if err != nil {
		t.Fatal(err)
	}
	list, _ := pyjson.Get(doc, "smb_shares")
	want, _ := pyjson.Items(list)
	m := migrateWithSMB(t, dir, golden.manifest.SecretKey.Value)
	var got []jsontext.Value
	if err := m.db.Read(t.Context(), func(tx *store.Tx) error {
		var err error
		got, err = smb.SharesTx(t.Context(), tx, 3)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if !sameRecords(got, want) || len(got) != 2 {
		t.Fatalf("shares\n got %s\nwant %s", got, want)
	}
	if d, _ := pyjson.Get(got[1], "domain"); string(d) != `""` {
		t.Errorf("empty domain: %s", d)
	}
	reported := false
	for _, e := range m.report.Entities {
		if e.Entity == "E22" {
			reported = e.Read == 2 && e.Written == 2
		}
	}
	for _, p := range m.report.Pending {
		if p.Entity == "E22" {
			t.Errorf("E22 still pending: %+v", p)
		}
	}
	if !reported {
		t.Errorf("report %+v", m.report.Entities)
	}
	shares := &smb.Shares{DB: m.db}
	f, err := shares.Lookup(t.Context(), 3, "bd543af85d954675b86ba49170a9ed37")
	if err != nil || f.Host != "files.golden.test" || f.Domain != "GOLDEN" || f.Username != "smbuser" || f.Share != "public" {
		t.Fatalf("lookup %+v %v", f, err)
	}
	upd, err := shares.Save(t.Context(), 3, smb.SaveRequest{ID: jsontext.Value(`"bd543af85d954675b86ba49170a9ed37"`),
		Name: jsontext.Value(`"Golden share"`), Host: jsontext.Value(`"files.golden.test"`), Share: jsontext.Value(`"public"`),
		Domain: jsontext.Value(`"GOLDEN"`), Username: jsontext.Value(`"other"`)})
	if err != nil {
		t.Fatal(err)
	}
	if c, _ := pyjson.Get(upd, "created_at"); string(c) != `"2026-11-02T09:03:54.250000+00:00"` {
		t.Errorf("created_at changed: %s", upd)
	}
}

// A document Python refuses to read stops the migration (STOP).
func TestSMBInvalidDocumentStops(t *testing.T) {
	for name, edit := range map[string]func(string) string{
		"secret member": func(s string) string {
			return strings.Replace(s, `"username": "smbuser",`, `"username": "smbuser", "password": "x",`, 1)
		},
		"not canonical":  func(s string) string { return strings.Replace(s, `"files.golden.test"`, `"Files.Golden.Test"`, 1) },
		"administrative": func(s string) string { return strings.Replace(s, `"public"`, `"C$"`, 1) },
		"missing timestamp": func(s string) string {
			return strings.Replace(s, `"created_at": "2026-11-02T09:03:54.250000+00:00",`, ``, 1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir := copyGolden(t)
			path := filepath.Join(dir, "users", "user_3", "smb_shares.json")
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			changed := edit(string(raw))
			if changed == string(raw) {
				t.Fatal("the edit did not apply")
			}
			writeLegacyFile(t, dir, "users/user_3/smb_shares.json", changed)
			o := testOptions(t, dir)
			o.Registry = smbM1Registry(t, M1{AdminUsers: []string{"cfg_admin"}, Persistent: &testPersistent{}})
			o.Secret = golden.manifest.SecretKey.Value
			_, err = startClosed(o)
			stop := assertStop(t, err, "E22")
			if !errors.Is(stop, smb.ErrInvalidLegacy) {
				t.Errorf("cause %v", stop)
			}
			assertNoGoDatabase(t, dir)
		})
	}
}
