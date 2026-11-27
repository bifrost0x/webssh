package backup

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/store"
)

var markSchema = store.Schema{Owner: "hosts", Migrations: []store.Migration{{Version: 1,
	SQL: `CREATE TABLE hosts_marks (v TEXT NOT NULL) STRICT`}}}

// installation builds a live data directory with a database holding mark
// and its material in go/.
func installation(t *testing.T, secret []byte, mark string) *Installation {
	t.Helper()
	dataDir := t.TempDir()
	goDir := filepath.Join(dataDir, keyring.GoDirName)
	if err := os.Mkdir(goDir, 0o700); err != nil {
		t.Fatal(err)
	}
	material, err := keyring.LoadOrCreateMaterial(dataDir, false)
	if err != nil {
		t.Fatal(err)
	}
	writeMarkDB(t, filepath.Join(goDir, keyring.DatabaseName), mark)
	path, _, err := keyring.MaterialLocation(dataDir, false)
	if err != nil {
		t.Fatal(err)
	}
	return &Installation{DataDir: dataDir, SecretKey: secret, MaterialPath: path, Material: material,
		Schemas: []store.Schema{markSchema}, Limits: DefaultLimits,
		Prepare: func(ctx context.Context, tx *store.Tx, p Prepared) error {
			_, err := tx.ExecContext(ctx, `INSERT INTO hosts_marks VALUES (?)`, "prepared:"+p.KeyID)
			return err
		}}
}

func writeMarkDB(t *testing.T, path, mark string) {
	t.Helper()
	db, err := store.Open(t.Context(), path, store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	err = db.ApplyAll(t.Context(), markSchema)
	if err == nil {
		err = db.Write(t.Context(), func(tx *store.Tx) error {
			_, err := tx.ExecContext(t.Context(), `INSERT INTO hosts_marks VALUES (?)`, mark)
			return err
		})
	}
	if err := errors.Join(err, db.CloseForActivation(t.Context())); err != nil {
		t.Fatal(err)
	}
}

func marks(t *testing.T, path string) []string {
	t.Helper()
	db, err := store.Open(t.Context(), path, store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var out []string
	err = db.Read(t.Context(), func(tx *store.Tx) error {
		rows, err := tx.QueryContext(t.Context(), `SELECT v FROM hosts_marks ORDER BY rowid`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var v string
			if err := rows.Scan(&v); err != nil {
				return err
			}
			out = append(out, v)
		}
		return rows.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// foreignArchive writes an archive of another installation with the same
// SECRET_KEY and other material.
func foreignArchive(t *testing.T, secret []byte, mark, reason string) (string, []byte, string) {
	t.Helper()
	dir := t.TempDir()
	material := bytes.Repeat([]byte{0x5a}, keyring.MaterialSize)
	ring, err := keyring.Open(secret, material)
	if err != nil {
		t.Fatal(err)
	}
	db := filepath.Join(dir, "src.db")
	writeMarkDB(t, db, mark)
	path := filepath.Join(dir, "a.tar")
	if err := WriteFile(path, Contents{Database: db, SecretKey: secret, Material: material, KeyID: ring.KeyID(),
		Reason: reason, Now: time.Now()}); err != nil {
		t.Fatal(err)
	}
	return path, material, ring.KeyID()
}

var testSecret = []byte("restore-test-secret-0123456789abcdef")

func stageForeign(t *testing.T, in *Installation, id string) (Staged, []byte, string) {
	t.Helper()
	archive, material, keyID := foreignArchive(t, testSecret, "restored", ReasonPurge)
	st, err := Stage(t.Context(), in, StageRequest{OperationID: id, Archive: archive})
	if err != nil {
		t.Fatal(err)
	}
	if st.Material == "" || st.KeyID != keyID || st.Export || st.Kind != KindGo {
		t.Fatalf("staged %+v", st)
	}
	goDir := filepath.Join(in.DataDir, keyring.GoDirName)
	if err := Commit(goDir, st, in, time.Now()); err != nil {
		t.Fatal(err)
	}
	return st, material, keyID
}

func assertRestored(t *testing.T, in *Installation, material []byte, keyID string) {
	t.Helper()
	got := marks(t, filepath.Join(in.DataDir, keyring.GoDirName, keyring.DatabaseName))
	if len(got) != 2 || got[0] != "restored" || got[1] != "prepared:"+keyID {
		t.Fatalf("database after restore: %v", got)
	}
	_, live, err := keyring.MaterialLocation(in.DataDir, false)
	if err != nil || !bytes.Equal(live, material) {
		t.Fatalf("material after restore: %v", err)
	}
	assertNoLeftovers(t, in.DataDir)
}

func assertNoLeftovers(t *testing.T, dataDir string) {
	t.Helper()
	entries, _ := os.ReadDir(filepath.Join(dataDir, keyring.GoDirName))
	for _, e := range entries {
		if len(e.Name()) > len(stagedPrefix) && e.Name()[:len(stagedPrefix)] == stagedPrefix {
			t.Fatalf("leftover %s", e.Name())
		}
	}
}

func TestRestoreGoArchiveFromAnotherHost(t *testing.T) {
	t.Parallel()
	in := installation(t, testSecret, "live")
	_, material, keyID := stageForeign(t, in, "op1")
	// The live database is untouched until activation.
	if got := marks(t, filepath.Join(in.DataDir, keyring.GoDirName, keyring.DatabaseName)); len(got) != 1 || got[0] != "live" {
		t.Fatalf("live database changed while staging: %v", got)
	}
	j, err := Activate(in.DataDir, time.Now)
	if err != nil || j.State != RestoreSucceeded {
		t.Fatalf("%+v, %v", j, err)
	}
	assertRestored(t, in, material, keyID)
	if state, _ := Status(filepath.Join(in.DataDir, keyring.GoDirName), time.Hour, time.Now()); state != string(RestoreSucceeded) {
		t.Fatalf("status %s", state)
	}
	if state, _ := Status(filepath.Join(in.DataDir, keyring.GoDirName), time.Minute, time.Now().Add(2*time.Minute)); state != "idle" {
		t.Fatalf("old status %s", state)
	}
}

// Crash injection: a crash after every checkpoint of the activation ends,
// after the next start, in the restored state.
func TestActivationCrashAtEveryPoint(t *testing.T) {
	t.Parallel()
	for _, p := range []string{PointPreviousKept, PointDatabaseRenamed, PointPreviousMaterial, PointMaterialInstalled, PointJournalDone} {
		t.Run(p, func(t *testing.T) {
			t.Parallel()
			in := installation(t, testSecret, "live")
			_, material, keyID := stageForeign(t, in, "crash")
			crashed := func() (crash bool) {
				defer func() { crash = recover() != nil }()
				_, _ = activate(in.DataDir, time.Now, func(at string) {
					if at == p {
						panic("crash")
					}
				})
				return false
			}()
			if !crashed {
				t.Fatalf("checkpoint %s not reached", p)
			}
			j, err := Activate(in.DataDir, time.Now)
			if err != nil || j.State != RestoreSucceeded {
				t.Fatalf("%+v, %v", j, err)
			}
			assertRestored(t, in, material, keyID)
		})
	}
}

// A failing activation puts back the previous database and material.
func TestActivationRollsBack(t *testing.T) {
	t.Parallel()
	in := installation(t, testSecret, "live")
	st, _, _ := stageForeign(t, in, "broken")
	// The staged material is damaged after Commit (wrong size).
	if err := os.WriteFile(st.Material, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	j, err := Activate(in.DataDir, time.Now)
	if err == nil || j.State != RestoreFailed {
		t.Fatalf("%+v, %v", j, err)
	}
	got := marks(t, filepath.Join(in.DataDir, keyring.GoDirName, keyring.DatabaseName))
	if len(got) != 1 || got[0] != "live" {
		t.Fatalf("database after rollback: %v", got)
	}
	_, live, err := keyring.MaterialLocation(in.DataDir, false)
	if err != nil || !bytes.Equal(live, in.Material) {
		t.Fatalf("material after rollback: %v", err)
	}
	assertNoLeftovers(t, in.DataDir)
	if blocked, _ := Blocked(filepath.Join(in.DataDir, keyring.GoDirName)); blocked {
		t.Fatal("a rolled back restore blocks the start")
	}
}

// A crash while the restore was being prepared changed nothing; the next
// start marks it failed and removes the staging files.
func TestInterruptedPreparation(t *testing.T) {
	t.Parallel()
	in := installation(t, testSecret, "live")
	goDir := filepath.Join(in.DataDir, keyring.GoDirName)
	if err := Begin(goDir, "prep", time.Now()); err != nil {
		t.Fatal(err)
	}
	if blocked, _ := Blocked(goDir); !blocked {
		t.Fatal("a restore in preparation does not block")
	}
	archive, _, _ := foreignArchive(t, testSecret, "restored", ReasonPurge)
	if _, err := Stage(t.Context(), in, StageRequest{OperationID: "prep", Archive: archive}); err != nil {
		t.Fatal(err)
	}
	j, err := Activate(in.DataDir, time.Now)
	if err != nil || j.State != RestoreFailed {
		t.Fatalf("%+v, %v", j, err)
	}
	if got := marks(t, filepath.Join(goDir, keyring.DatabaseName)); len(got) != 1 || got[0] != "live" {
		t.Fatalf("database: %v", got)
	}
	assertNoLeftovers(t, in.DataDir)
	if _, err := os.Lstat(stagedMaterialPath(in.MaterialPath, "prep")); err == nil {
		t.Fatal("staged material left behind")
	}
}

// An unreadable journal keeps the installation in maintenance (fail
// closed) and is never acted on.
func TestUnreadableJournalBlocks(t *testing.T) {
	t.Parallel()
	in := installation(t, testSecret, "live")
	goDir := filepath.Join(in.DataDir, keyring.GoDirName)
	if err := os.WriteFile(filepath.Join(goDir, JournalName), []byte(`{"state":"in_progress"`), 0o600); err != nil {
		t.Fatal(err)
	}
	if blocked, _ := Blocked(goDir); !blocked {
		t.Fatal("not blocked")
	}
	if j, err := Activate(in.DataDir, time.Now); !errors.Is(err, ErrJournal) || j.State != RestoreRollbackFailed {
		t.Fatalf("%+v, %v", j, err)
	}
	// A journal that points outside the installation is refused as well.
	bad := Journal{Format: journalFormat, OperationID: "x", State: RestoreInProgress, Staged: ".restore-x",
		Material: "/etc/passwd", MaterialPath: in.MaterialPath, PreviousMaterial: "/tmp/p"}
	if err := writeJournal(goDir, bad, time.Now()); err != nil {
		t.Fatal(err)
	}
	if j, err := Activate(in.DataDir, time.Now); err == nil || j.State != RestoreRollbackFailed {
		t.Fatalf("%+v, %v", j, err)
	}
}

func TestStageRefusesForeignSecretAndExports(t *testing.T) {
	t.Parallel()
	in := installation(t, testSecret, "live")
	archive, _, _ := foreignArchive(t, []byte("another-secret-0123456789abcdef0"), "restored", ReasonPurge)
	if _, err := Stage(t.Context(), in, StageRequest{OperationID: "s", Archive: archive}); !errors.Is(err, ErrSecretMismatch) {
		t.Fatalf("got %v", err)
	}
	assertNoLeftovers(t, in.DataDir)
	archive, _, _ = foreignArchive(t, testSecret, "restored", ReasonExport)
	st, err := Stage(t.Context(), in, StageRequest{OperationID: "e", Archive: archive})
	if err != nil || !st.Export {
		t.Fatalf("export: %+v, %v", st, err)
	}
	archive, _, _ = foreignArchive(t, testSecret, "restored", ReasonPurge)
	st, err = Stage(t.Context(), in, StageRequest{OperationID: "w", Archive: archive, Portable: true})
	if err != nil || !st.Export {
		t.Fatalf("web restore of a complete archive keeps credentials: %+v, %v", st, err)
	}
	junk := filepath.Join(t.TempDir(), "junk")
	if err := os.WriteFile(junk, bytes.Repeat([]byte("x"), 1024), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Stage(t.Context(), in, StageRequest{OperationID: "j", Archive: junk}); !errors.Is(err, ErrUnknownFormat) {
		t.Fatalf("junk: %v", err)
	}
}

func TestInspectGoArchive(t *testing.T) {
	t.Parallel()
	in := installation(t, testSecret, "live")
	in.Work = t.TempDir()
	archive, _, _ := foreignArchive(t, testSecret, "restored", ReasonExport)
	s, err := Inspect(t.Context(), in, archive)
	if err != nil || !s.Compatible || s.Kind != KindGo || s.FileCount != 3 || s.IncludesRemoteCredentials || s.Legacy {
		t.Fatalf("%+v, %v", s, err)
	}
	// A database with a schema version this build does not know (a newer
	// release) is not compatible.
	in.Schemas = []store.Schema{{Owner: "hosts", Migrations: []store.Migration{{Version: 1, SQL: `CREATE TABLE hosts_other (v TEXT) STRICT`}}}}
	if s, err := Inspect(t.Context(), in, archive); err != nil || s.Compatible || s.CompatibilityReason != ReasonNewer {
		t.Fatalf("%+v, %v", s, err)
	}
}
