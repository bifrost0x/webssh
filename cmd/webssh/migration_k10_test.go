package main

import (
	"crypto/sha256"
	"database/sql"
	json "encoding/json/v2"
	"errors"
	"io/fs"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/bifrost0x/webssh/internal/accounts"
	"github.com/bifrost0x/webssh/internal/auth/local"
	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/migrate/legacy"
	"github.com/bifrost0x/webssh/internal/platform"
	"github.com/bifrost0x/webssh/internal/settings"
	"github.com/bifrost0x/webssh/internal/store"
)

// k10Fixture is a legacy DATA_DIR of the golden data set: the generated
// fixture, the two real old releases and the extended boundary cases.
type k10Fixture struct{ name, archive string }

var k10Fixtures = []k10Fixture{
	{"golden", "../datadir.tar"}, // relative to goldenLegacyDir
	{"2fcd38a", "datadir-2fcd38a.tar"},
	{"v1.0.0", "datadir-v1.0.0.tar"},
	{"extended", "datadir-extended.tar"},
}

// k10Passwords maps every manifest account to its password: the golden
// manifest's users and the legacy manifest's passwords.
func k10Passwords(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	var golden struct {
		Values struct {
			Users map[string]struct {
				Password *string `json:"password"`
			} `json:"users"`
		} `json:"values"`
	}
	var old struct {
		Values struct {
			Passwords map[string]string `json:"passwords"`
		} `json:"values"`
	}
	for path, into := range map[string]any{"../../tests/golden/fixture/manifest.json": &golden, filepath.Join(goldenLegacyDir, "manifest.json"): &old} {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, into, json.RejectUnknownMembers(false)); err != nil {
			t.Fatal(err)
		}
	}
	for name, u := range golden.Values.Users {
		if u.Password != nil {
			out[name] = *u.Password
		}
	}
	maps.Copy(out, old.Values.Passwords)
	return out
}

// legacyFile is the I-01 state of one legacy file.
type legacyFile struct {
	sum   [32]byte
	size  int64
	mode  fs.FileMode
	mtime int64
}

// legacyState records every regular file and directory below dir.
func legacyState(t *testing.T, dir string) map[string]legacyFile {
	t.Helper()
	out := map[string]legacyFile{}
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, path)
		f := legacyFile{size: info.Size(), mode: info.Mode()}
		if info.Mode().IsRegular() {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			f.sum, f.mtime = sha256.Sum256(data), info.ModTime().UnixNano()
		} else if !info.IsDir() {
			t.Errorf("special file %s", rel)
		}
		if info.IsDir() {
			f.size = 0
		}
		out[rel] = f
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// assertLegacyUnchanged checks I-01 and I-19: every legacy file is
// unchanged, and everything new lies in the Go-owned paths (go/ and
// logs/.webssh-go/). Directory modes are not compared: the start narrows
// DATA_DIR, logs/ and keys/ to 0700 like the entrypoint.
func assertLegacyUnchanged(t *testing.T, dir string, before map[string]legacyFile) {
	t.Helper()
	after := legacyState(t, dir)
	for rel, b := range before {
		a, ok := after[rel]
		if !ok {
			t.Errorf("I-01: %s removed", rel)
			continue
		}
		if b.mode.IsDir() {
			if !a.mode.IsDir() {
				t.Errorf("I-01: directory %s replaced", rel)
			}
			continue
		}
		if a != b {
			t.Errorf("I-01: %s changed", rel)
		}
	}
	goOwned := []string{keyring.GoDirName, filepath.Join(keyring.LogsDirName, keyring.StateDirName)}
	for rel := range after {
		if _, ok := before[rel]; ok {
			continue
		}
		// The start creates the data subdirectories as the Python
		// entrypoint does (mkdir -p logs keys).
		if slices.Contains(platform.DataSubdirs, rel) && after[rel].mode.IsDir() {
			continue
		}
		if !slices.ContainsFunc(goOwned, func(p string) bool { return rel == p || strings.HasPrefix(rel, p+string(filepath.Separator)) }) {
			t.Errorf("I-19: %s written outside the Go-owned paths", rel)
		}
	}
}

// k10Env is the environment of a build-level migration of dir.
func k10Env(t *testing.T, dir string) (map[string]string, func(string) (string, bool)) {
	t.Helper()
	env := map[string]string{"DATA_DIR": dir, "SECRET_KEY": goldenSecret(t), "BACKUP_TEMP_DIR": t.TempDir()}
	return env, func(name string) (string, bool) { v, ok := env[name]; return v, ok }
}

// storedRecord reads coverage and pending of the migration record.
func storedRecord(t *testing.T, db *store.DB) (coverage []legacy.Coverage, pending []legacy.Pending, completed string) {
	t.Helper()
	var cov, pen string
	err := db.Read(t.Context(), func(tx *store.Tx) error {
		return tx.QueryRowContext(t.Context(), `SELECT coverage, pending, completed_at FROM migrate_record WHERE id = 1`).Scan(&cov, &pen, &completed)
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := errors.Join(json.Unmarshal([]byte(cov), &coverage), json.Unmarshal([]byte(pen), &pending)); err != nil {
		t.Fatal(err)
	}
	return coverage, pending, completed
}

// The build's registry migrates every entity of the specification as a
// step: nothing is left pending (KEEP-IN-PLACE), so the legacy purge is
// possible for every installation.
func TestBuildRegistryLeavesNothingPending(t *testing.T) {
	_, lookup := k10Env(t, t.TempDir())
	cfg, err := bootstrapConfig(lookup, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	reg, err := migrationRegistry(cfg, lookup)
	if err != nil {
		t.Fatal(err)
	}
	if missing := reg.Uncovered(); len(missing) > 0 {
		t.Fatalf("uncovered entities %v", missing)
	}
	if p := reg.PendingEntities(); len(p) > 0 {
		t.Fatalf("pending entities %v", p)
	}
	steps := reg.StepEntities()
	want := slices.Clone(legacy.Entities)
	slices.Sort(steps)
	slices.Sort(want)
	if !slices.Equal(steps, want) {
		t.Fatalf("steps %v, want every entity once", steps)
	}
}

// K10 over every legacy DATA_DIR of the golden data set with the build's
// complete registry: the dry run and the migration pass with every
// production verification, no entity is pending, the record covers all
// 54 entities as steps, the legacy files are unchanged (I-01, I-19),
// every account with a known password signs in, and a second start is S2
// and changes nothing (spec 8.1, idempotence).
func TestBuildMigratesEveryGoldenDataDir(t *testing.T) {
	passwords := k10Passwords(t)
	for _, fx := range k10Fixtures {
		t.Run(fx.name, func(t *testing.T) {
			dir := extractGolden(t, fx.archive)
			before := legacyState(t, dir)
			_, lookup := k10Env(t, dir)
			log := slog.New(slog.DiscardHandler)
			cfg, err := bootstrapConfig(lookup, log)
			if err != nil {
				t.Fatal(err)
			}
			o, err := migrationOptions(cfg, lookup)
			if err != nil {
				t.Fatal(err)
			}
			dry, err := legacy.DryRun(t.Context(), o)
			if err != nil {
				t.Fatalf("dry run: %v", err)
			}
			if len(dry.Pending) != 0 {
				t.Fatalf("dry run pending %+v", dry.Pending)
			}
			if _, err := os.Lstat(filepath.Join(dir, keyring.GoDirName, keyring.DatabaseName)); err == nil {
				t.Fatal("the dry run created the Go database")
			}
			assertLegacyUnchanged(t, dir, before)

			st, err := startMigration(t.Context(), cfg, lookup, log)
			if err != nil {
				t.Fatal(err)
			}
			if err := st.Close(); err != nil {
				t.Fatal(err)
			}
			if !st.Migrated || st.Report == nil {
				t.Fatalf("state %s, not migrated", st.State)
			}
			assertLegacyUnchanged(t, dir, before)
			if len(st.Report.Pending) != 0 {
				t.Fatalf("pending %+v", st.Report.Pending)
			}
			reported := map[string]bool{}
			for _, e := range st.Report.Entities {
				reported[e.Entity] = true
			}
			for _, e := range legacy.Entities {
				if !reported[e] {
					t.Errorf("%s missing from the report", e)
				}
			}
			if fx.name == "extended" {
				// Spec 8.3: sqlite_stat1, an extra index and an unknown table
				// are reported, not STOP.
				shape := st.Report.Source.SchemaShape
				if !slices.Contains(shape.Tables, "sqlite_stat1") || !slices.Contains(shape.Tables, "operator_notes") {
					t.Errorf("schema shape %+v", shape)
				}
			}
			// D-01: the previous behaviour is written as explicit settings
			// for every existing installation (spec section 6).
			for _, key := range []string{settings.PolicyDiscovery, settings.PolicyReachability,
				settings.PolicyLegacySSHAlgorithms, settings.PolicyTailnetFollowsSwitch} {
				if !slices.ContainsFunc(st.Report.MaterialisedSettings, func(m legacy.MaterialisedSetting) bool { return m.Setting == key }) {
					t.Errorf("D-01 setting %s not materialised", key)
				}
			}
			for _, e := range dry.Entities {
				if !reported[e.Entity] {
					t.Errorf("%s in the dry run only", e.Entity)
				}
			}

			db, err := store.Open(t.Context(), filepath.Join(dir, keyring.GoDirName, keyring.DatabaseName), store.Options{})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = db.Close() }()
			coverage, pending, completed := storedRecord(t, db)
			if len(pending) != 0 || len(coverage) != len(legacy.Entities) {
				t.Fatalf("record: %d covered, pending %+v", len(coverage), pending)
			}
			for _, c := range coverage {
				if c.Kind != legacy.CoverStep {
					t.Errorf("record coverage %+v", c)
				}
			}
			signInMigrated(t, db, passwords)
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}

			st2, err := startMigration(t.Context(), cfg, lookup, log)
			if err != nil {
				t.Fatal(err)
			}
			if err := st2.Close(); err != nil {
				t.Fatal(err)
			}
			if st2.Migrated || st2.State != legacy.S2 {
				t.Fatalf("second start: %s migrated=%v", st2.State, st2.Migrated)
			}
			db, err = store.Open(t.Context(), filepath.Join(dir, keyring.GoDirName, keyring.DatabaseName), store.Options{})
			if err != nil {
				t.Fatal(err)
			}
			if _, _, again := storedRecord(t, db); again != completed {
				t.Error("the second start rewrote the migration record")
			}
		})
	}
}

// signInMigrated signs in every migrated local account with a manifest password;
// locked accounts are refused.
func signInMigrated(t *testing.T, db *store.DB, passwords map[string]string) {
	t.Helper()
	type account struct {
		name   string
		locked bool
	}
	var list []account
	err := db.Read(t.Context(), func(tx *store.Tx) error {
		rows, err := tx.QueryContext(t.Context(), `SELECT username, is_locked FROM accounts_users WHERE managed_by = '' ORDER BY id`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var a account
			if err := rows.Scan(&a.name, &a.locked); err != nil {
				return err
			}
			list = append(list, a)
		}
		return rows.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	// The bcrypt hashes of the golden accounts dominate the run time, so
	// the accounts sign in concurrently; each one is checked as before.
	workers := min(4, runtime.GOMAXPROCS(0))
	hasher, err := local.NewHasher(local.Params{Memory: 64, Time: 1, Threads: 1, KeyLen: 32, SaltLen: 16}, workers)
	if err != nil {
		t.Fatal(err)
	}
	provider := &local.Provider{DB: db, Accounts: &accounts.Service{DB: db}, Hasher: hasher}
	var signed atomic.Int64
	var wg sync.WaitGroup
	slots := make(chan struct{}, workers)
	for _, a := range list {
		password, ok := passwords[a.name]
		if !ok {
			continue
		}
		var hash sql.NullString
		_ = db.Read(t.Context(), func(tx *store.Tx) error {
			return tx.QueryRowContext(t.Context(), `SELECT p.hash FROM authlocal_passwords p JOIN accounts_users u ON u.id = p.user_id WHERE u.username = ?`, a.name).Scan(&hash)
		})
		if !hash.Valid {
			continue // a local account without a password (password login off)
		}
		slots <- struct{}{}
		wg.Go(func() {
			defer func() { <-slots }()
			_, err := provider.Authenticate(t.Context(), a.name, password)
			switch {
			case a.locked && err == nil:
				t.Errorf("locked account %s signed in", a.name)
			case !a.locked && err != nil:
				t.Errorf("account %s: %v", a.name, err)
			case !a.locked:
				signed.Add(1)
			}
		})
	}
	wg.Wait()
	if signed.Load() == 0 {
		t.Error("no account signed in")
	}
}

// The legacy purge is possible for every installation: after the
// migration of each golden DATA_DIR with the build's registry nothing is
// pending, so `webssh legacy purge` writes and verifies its backup,
// removes the legacy data except secret_key, and the next start is S4
// with every account still signing in.
func TestBuildPurgesEveryGoldenDataDir(t *testing.T) {
	passwords := k10Passwords(t)
	for _, fx := range k10Fixtures {
		t.Run(fx.name, func(t *testing.T) {
			dir := extractGolden(t, fx.archive)
			env, lookup := k10Env(t, dir)
			for k, v := range env {
				t.Setenv(k, v)
			}
			log := slog.New(slog.DiscardHandler)
			cfg, err := bootstrapConfig(lookup, log)
			if err != nil {
				t.Fatal(err)
			}
			st, err := startMigration(t.Context(), cfg, lookup, log)
			if err != nil {
				t.Fatal(err)
			}
			if err := st.Close(); err != nil || !st.Migrated {
				t.Fatalf("migration: %s %v", st.State, err)
			}
			_, hadSecret := os.Lstat(filepath.Join(dir, "secret_key"))
			target := t.TempDir()
			code, out, e := runIn(t, "", "webssh", "legacy", "purge", "--backup-to", target, "--yes")
			if code != 0 {
				t.Fatalf("purge: %d %q %q", code, out, e)
			}
			if !strings.Contains(out, "Backup written and verified") {
				t.Fatalf("purge output %q", out)
			}
			if _, err := os.Lstat(filepath.Join(dir, "app.db")); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("app.db still present after the purge: %v", err)
			}
			// The purge removes the recorded files; directories may stay.
			_ = filepath.WalkDir(filepath.Join(dir, "users"), func(path string, d fs.DirEntry, err error) error {
				if err == nil && !d.IsDir() {
					t.Errorf("%s still present after the purge", path)
				}
				return nil
			})
			if _, err := os.Lstat(filepath.Join(dir, "secret_key")); hadSecret == nil && err != nil {
				t.Errorf("secret_key removed (I-08): %v", err)
			}
			st, err = startMigration(t.Context(), cfg, lookup, log)
			if err != nil {
				t.Fatal(err)
			}
			if err := st.Close(); err != nil || st.State != legacy.S4 {
				t.Fatalf("start after the purge: %s %v", st.State, err)
			}
			db, err := store.Open(t.Context(), filepath.Join(dir, keyring.GoDirName, keyring.DatabaseName), store.Options{})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = db.Close() }()
			signInMigrated(t, db, passwords)
		})
	}
}
