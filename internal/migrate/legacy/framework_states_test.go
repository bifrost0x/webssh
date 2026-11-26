package legacy

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	json "encoding/json/v2"

	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/store"
)

// The golden data set migrates (S1 to S2) with every legacy file unchanged,
// and a second start is S2 and changes nothing (section 8.1).
func TestStartMigratesGoldenDataSet(t *testing.T) {
	t.Parallel()
	dir := copyGolden(t)
	before := legacySnapshot(t, dir)
	o := testOptions(t, dir)
	st := mustStart(t, o)
	if st.State != S2 || !st.Migrated || st.ReportPath == "" {
		t.Fatalf("state %s, migrated %v, report %q", st.State, st.Migrated, st.ReportPath)
	}
	_ = st.Close()
	assertUntouched(t, dir, before)
	assertRegularOnly(t, dir)

	info, err := os.Stat(st.ReportPath)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("report mode: %v, %v", info, err)
	}
	var rep Report
	data, _ := os.ReadFile(st.ReportPath)
	if err := json.Unmarshal(data, &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Result != ResultCompleted || !rep.LegacyUntouched.Equal || !rep.Source.SecretChecked {
		t.Errorf("report: result %s, untouched %+v, secret checked %v", rep.Result, rep.LegacyUntouched, rep.Source.SecretChecked)
	}
	if len(rep.Pending) != 1 || rep.Pending[0] != (Pending{Entity: "E29", Phase: "B6", Count: 12}) {
		t.Errorf("pending %+v", rep.Pending)
	}
	wantCoverage := []Coverage{{"E23", 1, CoverStep}, {"A01", 1, CoverStep}, {"E35", 1, CoverStep}, {"E29", 0, CoverPending}}
	if !slices.Equal(rep.Coverage, wantCoverage) {
		t.Errorf("coverage %+v", rep.Coverage)
	}
	if strings.Contains(string(data), golden.manifest.SecretKey.Value) {
		t.Error("the report contains SECRET_KEY")
	}
	for _, k := range golden.manifest.Values.SSHKeys.Stored {
		if k.PlaintextB64 != "" && strings.Contains(string(data), string(mustB64(t, k.PlaintextB64))) {
			t.Errorf("the report contains key %s", k.Label)
		}
	}

	db, err := store.Open(t.Context(), filepath.Join(dir, "go", "webssh.db"), store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := StoredKeyID(t.Context(), db)
	if err != nil || keyID == "" {
		t.Fatalf("key id %q, %v", keyID, err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	for _, side := range sideFiles {
		if _, err := os.Lstat(filepath.Join(dir, "go", "webssh.db"+side)); err == nil {
			t.Errorf("side file %s left beside the database", side)
		}
	}

	before = legacySnapshot(t, dir)
	again, err := startClosed(o)
	if err != nil || again.State != S2 || again.Migrated {
		t.Fatalf("second start: %+v, %v", again, err)
	}
	assertUntouched(t, dir, before)
}

func TestStartFreshInstallation(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	st, err := startClosed(testOptions(t, dir))
	if err != nil || st.State != S0 {
		t.Fatalf("%+v, %v", st, err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "logs", ".webssh-go")); err == nil {
		t.Error("a fresh installation got logs/.webssh-go/ (I-25)")
	}
}

// S3: legacy data changed after the migration. Go does not start, and
// `migrate --replace` migrates again and keeps the old database.
func TestLegacyChangedNeedsReplace(t *testing.T) {
	t.Parallel()
	dir := copyGolden(t)
	o := testOptions(t, dir)
	if _, err := startClosed(o); err != nil {
		t.Fatal(err)
	}
	touchLegacy(t, dir)
	before := legacySnapshot(t, dir)
	if _, err := startClosed(o); stopCode(err) != CodeLegacyChanged || !strings.Contains(err.Error(), "migrate --replace") {
		t.Fatalf("err = %v", err)
	}
	assertUntouched(t, dir, before)
	res, err := Replace(t.Context(), o)
	if err != nil {
		t.Fatal(err)
	}
	if res.Database == "" || res.Report.ReplacedDatabase != res.Database {
		t.Fatalf("replaced %q, report %q", res.Database, res.Report.ReplacedDatabase)
	}
	if _, err := store.OpenReadOnly(t.Context(), res.Database, store.Shared); err != nil {
		t.Fatalf("kept database: %v", err)
	}
	assertUntouched(t, dir, before)
	if st, err := startClosed(o); err != nil || st.State != S2 {
		t.Fatalf("after replace: %+v, %v", st, err)
	}
}

// S1a: the Go database is gone but the marker says it existed (a Python
// restore without go/). With the marker removed too it is S1 (I-24).
func TestGoDataMissing(t *testing.T) {
	t.Parallel()
	dir := copyGolden(t)
	o := testOptions(t, dir)
	if _, err := startClosed(o); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(dir, "go")); err != nil {
		t.Fatal(err)
	}
	if _, err := startClosed(o); stopCode(err) != CodeGoDataMissing {
		t.Fatalf("err = %v", err)
	}
	if res, err := Replace(t.Context(), o); err != nil || res.Database != "" {
		t.Fatalf("replace in S1a: %+v, %v", res, err)
	}
	if st, err := startClosed(o); err != nil || st.State != S2 {
		t.Fatalf("after replace: %+v, %v", st, err)
	}
	if err := os.RemoveAll(filepath.Join(dir, "go")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "logs", ".webssh-go", "migrated")); err != nil {
		t.Fatal(err)
	}
	if st, err := startClosed(o); err != nil || !st.Migrated {
		t.Fatalf("%+v, %v", st, err)
	}
}

// S5: legacy data gone without a purge: start with a warning.
func TestLegacyMissing(t *testing.T) {
	t.Parallel()
	dir := copyGolden(t)
	o := testOptions(t, dir)
	if _, err := startClosed(o); err != nil {
		t.Fatal(err)
	}
	for _, name := range append(legacyIndicators, "app.db") {
		_ = os.RemoveAll(filepath.Join(dir, name))
	}
	st, err := startClosed(o)
	if err != nil || st.State != S5 || len(st.Warnings) == 0 || st.Warnings[0].Code != "legacy_missing" {
		t.Fatalf("%+v, %v", st, err)
	}
}

// S7: a damaged Go database, a partial legacy source and a database
// without a record beside legacy data all stop without writing.
func TestUnknownStates(t *testing.T) {
	t.Parallel()
	t.Run("damaged database", func(t *testing.T) {
		dir := copyGolden(t)
		o := testOptions(t, dir)
		if _, err := startClosed(o); err != nil {
			t.Fatal(err)
		}
		db := filepath.Join(dir, "go", "webssh.db")
		data, _ := os.ReadFile(db)
		for i := 4096; i < len(data) && i < 3*4096; i++ {
			data[i] ^= 0xff
		}
		if err := os.WriteFile(db, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := startClosed(o); stopCode(err) != CodeGoDatabase {
			t.Fatalf("err = %v", err)
		}
		if _, err := Replace(t.Context(), o); stopCode(err) != CodeReplaceDamaged {
			t.Fatalf("replace: %v", err)
		}
		if after, _ := os.ReadFile(db); string(after) != string(data) {
			t.Error("the damaged database was changed")
		}
	})
	t.Run("partial legacy source", func(t *testing.T) {
		dir := copyGolden(t)
		if err := os.Remove(filepath.Join(dir, "app.db")); err != nil {
			t.Fatal(err)
		}
		before := legacySnapshot(t, dir)
		if _, err := startClosed(testOptions(t, dir)); stopCode(err) != CodeLegacyUnknown {
			t.Fatalf("err = %v", err)
		}
		assertUntouched(t, dir, before)
	})
	t.Run("database without record beside legacy data", func(t *testing.T) {
		dir := copyGolden(t)
		if err := os.MkdirAll(filepath.Join(dir, "go"), 0o700); err != nil {
			t.Fatal(err)
		}
		db, err := store.Open(t.Context(), filepath.Join(dir, "go", "webssh.db"), store.Options{})
		if err != nil {
			t.Fatal(err)
		}
		if err := errors.Join(db.ApplyAll(t.Context(), RecordSchema()), db.Close()); err != nil {
			t.Fatal(err)
		}
		if _, err := startClosed(testOptions(t, dir)); stopCode(err) != CodeGoDatabase {
			t.Fatalf("err = %v", err)
		}
	})
}

// S9: the keyring material is missing; nothing is written. Restoring the
// file starts normally; --replace moves the old database aside before it
// creates new material (I-23, I-27).
func TestKeyMaterialMissing(t *testing.T) {
	t.Parallel()
	dir := copyGolden(t)
	o := testOptions(t, dir)
	if _, err := startClosed(o); err != nil {
		t.Fatal(err)
	}
	material := filepath.Join(dir, "logs", ".webssh-go", keyring.MaterialName)
	saved, err := os.ReadFile(material)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(material); err != nil {
		t.Fatal(err)
	}
	dbBefore, _ := os.ReadFile(filepath.Join(dir, "go", "webssh.db"))
	if _, err := startClosed(o); stopCode(err) != CodeKeyMaterial {
		t.Fatalf("err = %v", err)
	}
	if _, err := os.Lstat(material); err == nil {
		t.Fatal("S9 created new material while a Go database exists")
	}
	if err := os.WriteFile(material, saved, 0o600); err != nil {
		t.Fatal(err)
	}
	if st, err := startClosed(o); err != nil || st.State != S2 {
		t.Fatalf("with the material restored: %+v, %v", st, err)
	}
	// Foreign material: S9, then --replace.
	foreign := make([]byte, keyring.MaterialSize)
	foreign[0] = 1
	if err := os.WriteFile(material, foreign, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := startClosed(o); stopCode(err) != CodeKeyMaterial {
		t.Fatalf("foreign material: %v", err)
	}
	res, err := Replace(t.Context(), o)
	if err != nil {
		t.Fatal(err)
	}
	moved, err := os.ReadFile(res.Database)
	if err != nil || string(moved) != string(dbBefore) {
		t.Fatalf("the old database was not moved byte for byte: %v", err)
	}
	if got, _ := os.ReadFile(filepath.Join(filepath.Dir(res.Database), "keyring-material-logs")); string(got) != string(foreign) {
		t.Error("the foreign material was not moved aside")
	}
	if fresh, _ := os.ReadFile(material); len(fresh) != keyring.MaterialSize || string(fresh) == string(foreign) {
		t.Error("no new material after --replace in S9")
	}
	if st, err := startClosed(o); err != nil || st.State != S2 {
		t.Fatalf("after replace: %+v, %v", st, err)
	}
}

// Condition F2: material only in go/ beside legacy data moves to
// logs/.webssh-go/ before anything starts, also when a crash left both
// copies.
func TestMaterialInGoMovesToState(t *testing.T) {
	t.Parallel()
	dir := copyGolden(t)
	o := testOptions(t, dir)
	if _, err := startClosed(o); err != nil {
		t.Fatal(err)
	}
	inState := filepath.Join(dir, "logs", ".webssh-go", keyring.MaterialName)
	inGo := filepath.Join(dir, "go", keyring.MaterialName)
	material, _ := os.ReadFile(inState)
	if err := os.Rename(inState, inGo); err != nil {
		t.Fatal(err)
	}
	st, err := startClosed(o)
	if err != nil || st.State != S2 || !slices.ContainsFunc(st.Warnings, func(w Warning) bool { return w.Code == "keyring_material_moved" }) {
		t.Fatalf("%+v, %v", st, err)
	}
	if _, err := os.Lstat(inGo); err == nil {
		t.Error("material still in go/")
	}
	if got, _ := os.ReadFile(inState); string(got) != string(material) {
		t.Error("material not in logs/.webssh-go/")
	}
	// A crash after the copy and before the removal leaves both copies.
	if err := os.WriteFile(inGo, material, 0o600); err != nil {
		t.Fatal(err)
	}
	if st, err := startClosed(o); err != nil || st.State != S2 {
		t.Fatalf("%+v, %v", st, err)
	}
	if _, err := os.Lstat(inGo); err == nil {
		t.Error("identical copy in go/ not removed")
	}
	// Before the first migration: material copied into go/ by hand.
	fresh := copyGolden(t)
	if err := os.MkdirAll(filepath.Join(fresh, "go"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fresh, "go", keyring.MaterialName), material, 0o600); err != nil {
		t.Fatal(err)
	}
	if st, err := startClosed(testOptions(t, fresh)); err != nil || !st.Migrated {
		t.Fatalf("%+v, %v", st, err)
	}
	if _, err := os.Lstat(filepath.Join(fresh, "go", keyring.MaterialName)); err == nil {
		t.Error("material left in go/ after the first migration")
	}
	if got, _ := os.ReadFile(filepath.Join(fresh, "logs", ".webssh-go", keyring.MaterialName)); string(got) != string(material) {
		t.Error("the migration did not use the material it found")
	}
}
