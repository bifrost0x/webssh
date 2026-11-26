package settings

import (
	"archive/tar"
	"encoding/json/jsontext"
	"errors"
	"io"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/bifrost0x/webssh/internal/store"
)

// goldenFile returns a file of the golden DATA_DIR written by the Python
// release (tests/golden).
func goldenFile(t *testing.T, name string) []byte {
	t.Helper()
	f, err := os.Open("../../tests/golden/fixture/datadir.tar")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	tr := tar.NewReader(f)
	for {
		h, err := tr.Next()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if h.Name == name {
			b, err := io.ReadAll(tr)
			if err != nil {
				t.Fatal(err)
			}
			return b
		}
	}
}

func write(t *testing.T, db *store.DB, fn func(tx *store.Tx) error) {
	t.Helper()
	if err := db.Write(t.Context(), fn); err != nil {
		t.Fatal(err)
	}
}

func TestImportUserKeepsEveryKey(t *testing.T) {
	s, db := newService(t, Environment{})
	doc := jsontext.Value(`{"schema_version":2,"theme":"removed-theme","notepad":"text","workspace_presets":[{"id":"p"}],` +
		`"intro_tour":"dismissed","future_key":{"n":123456789012345678901},"recovery_reviewed_at":"",` +
		`"overview_panels":[{"id":"future","w":4},{"id":"hosts","w":5}]}`)
	var res UserImport
	write(t, db, func(tx *store.Tx) error {
		var err error
		res, err = ImportUser(t.Context(), tx, 4, doc, 1)
		return err
	})
	if res.Notepad != "text" || string(res.WorkspacePresets) != `[{"id":"p"}]` {
		t.Errorf("routed values %+v", res)
	}
	if !slices.Equal(res.Keys, []string{"future_key", "intro_tour", "overview_panels", "recovery_reviewed_at", "theme"}) || res.Materialised != nil {
		t.Errorf("keys %v materialised %v", res.Keys, res.Materialised)
	}
	u, err := s.User(t.Context(), 4)
	if err != nil {
		t.Fatal(err)
	}
	// A theme a later release removed still loads; the number above 2^53
	// keeps its digits.
	if u.Theme != "removed-theme" || string(u.Document()["future_key"]) != `{"n":123456789012345678901}` {
		t.Errorf("imported %s", docJSON(t, u))
	}
	if string(u.overviewPanelsValue()) != `[{"id":"hosts","w":5}]` {
		t.Errorf("panels %s", u.overviewPanelsValue())
	}
	write(t, db, func(tx *store.Tx) error { return VerifyUser(t.Context(), tx, 4, doc, 1) })
	// A later save keeps the unknown key.
	u, _ = s.Update(t.Context(), 4, Changes{Theme: new("noir")})
	if _, ok := u.Document()["future_key"]; !ok {
		t.Error("save dropped an unknown key")
	}
}

func TestImportUserMaterialisesOldDefault(t *testing.T) {
	s, db := newService(t, Environment{})
	write(t, db, func(tx *store.Tx) error {
		// Generation 0 without a file: confirm_session_close was true.
		res, err := ImportUser(t.Context(), tx, 1, nil, 0)
		if err != nil || !slices.Equal(res.Materialised, []string{keyConfirmSessionClose}) {
			t.Errorf("%+v %v", res, err)
		}
		// An explicit false wins over the old default.
		if _, err := ImportUser(t.Context(), tx, 2, jsontext.Value(`{"schema_version":2,"confirm_session_close":false}`), 0); err != nil {
			return err
		}
		// Generation 1 gets the default of this release.
		_, err = ImportUser(t.Context(), tx, 3, nil, 1)
		return err
	})
	for id, want := range map[int64]bool{1: true, 2: false, 3: false} {
		if u, _ := s.User(t.Context(), id); u.ConfirmSessionClose != want {
			t.Errorf("account %d: confirm_session_close %v", id, u.ConfirmSessionClose)
		}
	}
	write(t, db, func(tx *store.Tx) error { return VerifyUser(t.Context(), tx, 1, nil, 0) })
	if err := db.Read(t.Context(), func(tx *store.Tx) error { return VerifyUser(t.Context(), tx, 3, nil, 0) }); err == nil {
		t.Error("verification missed a difference")
	}
}

func TestImportUserRefusesInvalidDocuments(t *testing.T) {
	_, db := newService(t, Environment{})
	for _, doc := range []string{`[]`, `{}`, `{"schema_version":1}`, `{"schema_version":2,"theme":1}`,
		`{"schema_version":2,"notepad":5}`, `{"schema_version":2,"theme":"a","theme":"b"}`} {
		err := db.Write(t.Context(), func(tx *store.Tx) error {
			_, err := ImportUser(t.Context(), tx, 1, jsontext.Value(doc), 1)
			return err
		})
		if !errors.Is(err, ErrLegacyDocument) {
			t.Errorf("%s: %v", doc, err)
		}
	}
}

func TestImportGoldenSettings(t *testing.T) {
	s, db := newService(t, Environment{})
	app := goldenFile(t, "data/app_settings.json")
	user := goldenFile(t, "data/users/user_3/settings.json")
	write(t, db, func(tx *store.Tx) error {
		if _, err := ImportApp(t.Context(), tx, app, 1); err != nil {
			return err
		}
		if _, err := ImportUser(t.Context(), tx, 3, user, 1); err != nil {
			return err
		}
		if err := VerifyApp(t.Context(), tx, app); err != nil {
			return err
		}
		return VerifyUser(t.Context(), tx, 3, user, 1)
	})
	a, err := s.App(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	// The fixture hides the support links and turned credentials and
	// automation on; everything else is a default.
	if a.SupportLinksEnabled || !a.CredentialsEnabled || !a.AutomationEnabled || !a.TailnetRouteRestricted {
		t.Errorf("effective %+v", a)
	}
	if a.rows["credentials_enabled_revision"].source != SourceMigrated {
		t.Error("source of a migrated value")
	}
}

func TestImportAppRefusals(t *testing.T) {
	_, db := newService(t, Environment{})
	for _, doc := range []string{
		`{"schema_version":2,"credentials_enabled":1}`,
		`{"schema_version":2,"audit_backup_count":91}`,
		`{"schema_version":2,"ratelimit_ipv6_prefix":47}`,
		`{"schema_version":2,"runtime_feature_migration":["nope"]}`,
		`{"schema_version":2,"automation_enabled_revision":5}`,
		`{"schema_version":2,"ssh.legacy_algorithms":true}`,
		`{"credentials_enabled":true}`,
	} {
		err := db.Write(t.Context(), func(tx *store.Tx) error {
			_, err := ImportApp(t.Context(), tx, jsontext.Value(doc), 1)
			return err
		})
		if !errors.Is(err, ErrLegacyDocument) {
			t.Errorf("%s: %v", doc, err)
		}
	}
}

func TestRecoveryCheck(t *testing.T) {
	s, db := newService(t, Environment{})
	write(t, db, func(tx *store.Tx) error {
		return ImportRecoveryCheck(t.Context(), tx, jsontext.Value(`{"restored_at": "2026-11-02T09:00:00+00:00"}`), 1)
	})
	a, _ := s.App(t.Context())
	if string(a.rows["recovery_check"].value) != `{"restored_at":"2026-11-02T09:00:00+00:00"}` {
		t.Errorf("%s", a.rows["recovery_check"].value)
	}
	big := jsontext.Value(`"` + strings.Repeat("x", 600) + `"`)
	if err := db.Write(t.Context(), func(tx *store.Tx) error { return ImportRecoveryCheck(t.Context(), tx, big, 1) }); err == nil {
		t.Error("oversized notice accepted")
	}
}
