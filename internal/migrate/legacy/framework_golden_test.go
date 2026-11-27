package legacy

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/bifrost0x/webssh/internal/settings"
	"github.com/bifrost0x/webssh/internal/store"
)

// Every DATA_DIR the real Python releases wrote migrates with the
// framework, the example step and the test steps, and the legacy files
// stay unchanged (I-01). The extended set also carries a recovery check,
// persistent tmux sessions, an LDAP fence and single-user stores.
func TestMigrateRealLegacyDataDirs(t *testing.T) {
	t.Parallel()
	for _, archive := range []string{"datadir-extended.tar", "datadir-v1.0.0.tar", "datadir-2fcd38a.tar"} {
		t.Run(archive, func(t *testing.T) {
			t.Parallel()
			dir := extractLegacy(t, archive)
			before := legacySnapshot(t, dir)
			o := testOptions(t, dir)
			o.Secret = legacyFixture(t).SecretKey.Value
			st, err := startClosed(o)
			if err != nil || !st.Migrated {
				t.Fatalf("%+v, %v", st, err)
			}
			assertUntouched(t, dir, before)
			assertRegularOnly(t, dir)
			rep := st.Report
			var e35 *StepReport
			for i := range rep.Entities {
				if rep.Entities[i].Entity == "E35" {
					e35 = &rep.Entities[i]
				}
			}
			if archive == "datadir-extended.tar" {
				var paths []string
				for _, k := range e35.KeptInPlace {
					paths = append(paths, k.Path)
				}
				if !slices.Equal(paths, []string{"profiles.json", "keys", "commands"}) {
					t.Errorf("E35 kept in place: %v", paths)
				}
				sessions := countRows(t, dir, "hostops_c7_sessions")
				if sessions != 2 {
					t.Errorf("persistent sessions migrated: %d", sessions)
				}
			}
			if again, err := startClosed(o); err != nil || again.State != S2 {
				t.Fatalf("second start: %+v, %v", again, err)
			}
		})
	}
}

// Determinism (section 8.1): two migrations of the same source give the
// same keys, the same coverage and the same digest.
func TestMigrationIsDeterministic(t *testing.T) {
	t.Parallel()
	var digests, keys []string
	for range 2 {
		dir := copyGolden(t)
		st, err := startClosed(testOptions(t, dir))
		if err != nil {
			t.Fatal(err)
		}
		digests = append(digests, st.Report.Source.Digest)
		keys = append(keys, strings.Join(keyIDs(t, dir), ","))
	}
	if digests[0] != digests[1] || keys[0] != keys[1] || keys[0] == "" {
		t.Fatalf("digests %v, keys %v", digests, keys)
	}
}

func countRows(t *testing.T, dir, table string) int {
	t.Helper()
	var n int
	withDB(t, dir, func(tx *store.Tx) error {
		return tx.QueryRowContext(context.Background(), `SELECT count(*) FROM `+table).Scan(&n) // #nosec G202 -- test table names
	})
	return n
}

func keyIDs(t *testing.T, dir string) []string {
	t.Helper()
	var ids []string
	withDB(t, dir, func(tx *store.Tx) error {
		rows, err := tx.QueryContext(context.Background(), `SELECT id FROM hostops_c7_keys ORDER BY id`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return err
			}
			ids = append(ids, id)
		}
		return rows.Err()
	})
	return ids
}

func withDB(t *testing.T, dir string, fn func(*store.Tx) error) {
	t.Helper()
	db, err := store.Open(t.Context(), filepath.Join(dir, "go", "webssh.db"), store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Read(t.Context(), fn); err != nil {
		t.Fatal(err)
	}
}

// The DoD of the plan: the report names every pending entity with its
// count, and a failed migration leaves a report with the cause.
func TestReportNamesPendingAndFailures(t *testing.T) {
	t.Parallel()
	dir := copyGolden(t)
	o := testOptions(t, dir)
	o.Origin = OriginRule{KeepLegacyScheme: true, Evidence: "CORS_ORIGINS=*, TRUSTED_PROXIES=0"}
	st, err := startClosed(o)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Report.Pending) != 1 || st.Report.Pending[0].Count == 0 {
		t.Errorf("pending: %+v", st.Report.Pending)
	}
	if !slices.ContainsFunc(st.Report.MaterialisedSettings, func(s MaterialisedSetting) bool {
		return s.Setting == settings.PolicyOriginIgnoreScheme && s.Evidence == "CORS_ORIGINS=*, TRUSTED_PROXIES=0"
	}) {
		t.Errorf("origin setting not reported: %+v", st.Report.MaterialisedSettings)
	}
	db, err := store.Open(t.Context(), filepath.Join(dir, "go", "webssh.db"), store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	// The setting has one owner, internal/settings; the migration keeps
	// no copy of its own.
	var value, source string
	if err := db.Read(t.Context(), func(tx *store.Tx) error {
		return tx.QueryRowContext(t.Context(), `SELECT value, source FROM settings_app WHERE key = ?`, settings.PolicyOriginIgnoreScheme).Scan(&value, &source)
	}); err != nil || value != "true" || source != "materialised" {
		t.Errorf("setting: %q %q %v", value, source, err)
	}
	var copies int
	if err := db.Read(t.Context(), func(tx *store.Tx) error {
		return tx.QueryRowContext(t.Context(), `SELECT count(*) FROM sqlite_schema WHERE name LIKE 'migrate_settings%'`).Scan(&copies)
	}); err != nil || copies != 0 {
		t.Errorf("migrate_settings: %d %v", copies, err)
	}
	_ = db.Close()

	failing := copyGolden(t)
	fo := testOptions(t, failing)
	fo.Secret += "x"
	if _, err := startClosed(fo); err == nil {
		t.Fatal("no error")
	}
	reports, _ := filepath.Glob(filepath.Join(failing, "go", reportPrefix+"*.json"))
	if len(reports) != 1 {
		t.Fatalf("failure reports: %v", reports)
	}
	data, _ := os.ReadFile(reports[0])
	if !strings.Contains(string(data), `"result":"failed"`) || !strings.Contains(string(data), CodeSecretMismatch) {
		t.Errorf("failure report: %s", data)
	}
}

func TestRegistryRules(t *testing.T) {
	t.Parallel()
	r := NewRegistry()
	if err := AddSingleUserStores(r); err != nil {
		t.Fatal(err)
	}
	if err := AddSingleUserStores(r); err == nil {
		t.Error("an entity registered twice")
	}
	if err := r.KeepInPlace("E35", "B1", func(context.Context, *Source) (int, error) { return 0, nil }); err == nil {
		t.Error("a step entity registered as pending")
	}
	if err := r.KeepInPlace("E99", "B1", func(context.Context, *Source) (int, error) { return 0, nil }); err == nil {
		t.Error("an unknown entity registered")
	}
	if err := r.KeepInPlace("E22", "", nil); err == nil {
		t.Error("pending without phase")
	}
	if len(Entities) != 54 || len(r.Uncovered()) != 53 {
		t.Errorf("entities %d, uncovered %d", len(Entities), len(r.Uncovered()))
	}
}

type versionedStep struct {
	Step
	wrapped *int
}

func (s versionedStep) Read(ctx context.Context, src *Source) error {
	*s.wrapped++
	return s.Step.Read(ctx, src)
}

// StepEntities, PendingEntities and WrapSteps describe and instrument a
// build's registry; a wrapped step still runs, and a wrapper that changes
// the entity is refused by the run.
func TestRegistryListsAndWrapsSteps(t *testing.T) {
	t.Parallel()
	r := NewRegistry()
	if err := AddSingleUserStores(r); err != nil {
		t.Fatal(err)
	}
	if err := r.KeepInPlace("E22", "B4", func(context.Context, *Source) (int, error) { return 0, nil }); err != nil {
		t.Fatal(err)
	}
	if got := r.StepEntities(); len(got) != 1 || got[0] != "E35" {
		t.Errorf("steps %v", got)
	}
	if got := r.PendingEntities(); len(got) != 1 || got[0] != "E22" {
		t.Errorf("pending %v", got)
	}
	n := 0
	r.WrapSteps(func(s Step) Step { return versionedStep{Step: s, wrapped: &n} })
	segs, err := r.segments(false)
	if err != nil || len(segs) != 1 || segs[0].step == nil {
		t.Fatalf("%v %v", segs, err)
	}
	if _, ok := segs[0].step.(versionedStep); !ok {
		t.Fatalf("step not wrapped: %T", segs[0].step)
	}
	r.WrapSteps(func(Step) Step { return &discardStep{def: discardedEntities[0]} })
	if _, err := r.segments(false); err == nil {
		t.Error("a wrapper that changes the entity was accepted")
	}
}
