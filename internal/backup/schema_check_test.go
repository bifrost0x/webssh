package backup

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/store"
)

// craftedArchive writes an archive of another installation whose
// database ran extra after the mark schema: what anyone holding an
// archive can produce, since the ledger checksums are those of the
// published migrations.
func craftedArchive(t *testing.T, schemas []store.Schema, extra string) string {
	t.Helper()
	dir := t.TempDir()
	material := bytes.Repeat([]byte{0x5a}, keyring.MaterialSize)
	ring, err := keyring.Open(testSecret, material)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "src.db")
	db, err := store.Open(t.Context(), path, store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	err = db.ApplyAll(t.Context(), schemas...)
	if err == nil {
		err = db.Write(t.Context(), func(tx *store.Tx) error {
			if _, err := tx.ExecContext(t.Context(), `INSERT INTO hosts_marks VALUES ('restored')`); err != nil {
				return err
			}
			if extra == "" {
				return nil
			}
			_, err := tx.ExecContext(t.Context(), extra)
			return err
		})
	}
	if err := errors.Join(err, db.CloseForActivation(t.Context())); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(dir, "a.tar")
	if err := WriteFile(archive, Contents{Database: path, SecretKey: testSecret, Material: material, KeyID: ring.KeyID(),
		Reason: ReasonPurge, Now: time.Now()}); err != nil {
		t.Fatal(err)
	}
	return archive
}

// A restored Go archive may only hold the schema this build creates:
// triggers, views, objects outside the owners' prefixes and changed
// definitions are refused by the upload check and by the restore, before
// any statement of the restore runs against the archive's database.
func TestRestoreRefusesForeignSchemaObjects(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"trigger":               `CREATE TRIGGER hosts_x AFTER INSERT ON hosts_marks BEGIN DELETE FROM hosts_marks; END`,
		"trigger on the ledger": `CREATE TRIGGER hosts_y AFTER INSERT ON store_migrations BEGIN SELECT 1; END`,
		"view":                  `CREATE VIEW hosts_v AS SELECT v FROM hosts_marks`,
		"foreign table":         `CREATE TABLE evil (a TEXT)`,
		"changed table":         `ALTER TABLE hosts_marks ADD COLUMN extra TEXT`,
		"extra index":           `CREATE INDEX hosts_marks_v ON hosts_marks (v)`,
	}
	for name, extra := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			in := installation(t, testSecret, "live")
			in.Work = t.TempDir()
			prepared := false
			prepare := in.Prepare
			in.Prepare = func(ctx context.Context, tx *store.Tx, p Prepared) error {
				prepared = true
				return prepare(ctx, tx, p)
			}
			archive := craftedArchive(t, in.Schemas, extra)
			if _, err := Inspect(t.Context(), in, archive); !errors.Is(err, ErrInvalid) {
				t.Errorf("upload check accepted the archive: %v", err)
			}
			if _, err := Stage(t.Context(), in, StageRequest{OperationID: "s", Archive: archive}); !errors.Is(err, ErrInvalid) {
				t.Errorf("restore accepted the archive: %v", err)
			}
			if prepared {
				t.Error("the restore semantics ran on the archive's database")
			}
			assertNoLeftovers(t, in.DataDir)
		})
	}
}

// An archive of an earlier release, whose schema lacks later migrations,
// is brought up to this build and then matches its schema exactly.
func TestRestoreAcceptsAnOlderSchema(t *testing.T) {
	t.Parallel()
	in := installation(t, testSecret, "live")
	in.Work = t.TempDir()
	newer := store.Schema{Owner: "hosts", Migrations: append(slices.Clone(markSchema.Migrations),
		store.Migration{Version: 2, SQL: `CREATE TABLE hosts_more (n INTEGER) STRICT; CREATE INDEX hosts_marks_v ON hosts_marks (v)`})}
	archive := craftedArchive(t, []store.Schema{markSchema}, "")
	in.Schemas = []store.Schema{newer}
	if s, err := Inspect(t.Context(), in, archive); err != nil || !s.Compatible {
		t.Fatalf("upload check: %+v, %v", s, err)
	}
	if _, err := Stage(t.Context(), in, StageRequest{OperationID: "o", Archive: archive}); err != nil {
		t.Fatalf("restore of an older schema: %v", err)
	}
}

// Verify (the purge backup) has no schemas to compare with; it still
// refuses triggers and views.
func TestVerifyRefusesTriggers(t *testing.T) {
	t.Parallel()
	archive := craftedArchive(t, []store.Schema{markSchema},
		`CREATE TRIGGER hosts_x AFTER UPDATE ON hosts_marks BEGIN SELECT 1; END`)
	if _, err := VerifyWith(t.Context(), archive, VerifyOptions{Secret: testSecret}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("verify accepted a trigger: %v", err)
	}
	if _, err := os.Stat(archive); err != nil {
		t.Fatal(err)
	}
}
