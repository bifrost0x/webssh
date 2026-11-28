package main

import (
	"archive/tar"
	json "encoding/json/v2"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/backup"
	"github.com/bifrost0x/webssh/internal/store"
)

// rewriteGoArchive copies a Go archive and runs sql on its database
// before writing it again with the archive's own SECRET_KEY, material and
// key id: what anyone holding an archive can produce.
func rewriteGoArchive(t *testing.T, archive, sql string) string {
	t.Helper()
	f, err := os.Open(archive)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "webssh.db")
	var m backup.Manifest
	small := map[string][]byte{}
	tr := tar.NewReader(f)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		switch h.Name {
		case backup.ManifestName:
			if err := json.Unmarshal(data, &m); err != nil {
				t.Fatal(err)
			}
		case backup.DatabaseName:
			if err := os.WriteFile(dbPath, data, 0o600); err != nil {
				t.Fatal(err)
			}
		default:
			small[h.Name] = data
		}
	}
	db, err := store.Open(t.Context(), dbPath, store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	err = db.Write(t.Context(), func(tx *store.Tx) error {
		_, err := tx.ExecContext(t.Context(), sql)
		return err
	})
	if err := errors.Join(err, db.CloseForActivation(t.Context())); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "evil.tar")
	if err := backup.WriteFile(out, backup.Contents{Database: dbPath, SecretKey: small[backup.SecretName],
		Material: small[backup.MaterialName], KeyID: m.KeyID, Reason: m.Reason, Now: time.Now()}); err != nil {
		t.Fatal(err)
	}
	return out
}

const evilPurgeTrigger = `
CREATE TRIGGER x_carry_upd AFTER UPDATE ON migrate_keyring BEGIN
  INSERT OR REPLACE INTO migrate_purge (id, in_progress, files, backup, started_at, completed_at)
  VALUES (1, 1, '["app.db","secret_key","logs/.webssh-go/keyring-material"]', '', '2026-11-28T00:00:00Z', '');
END;
CREATE TRIGGER x_carry_ins AFTER INSERT ON migrate_keyring BEGIN
  INSERT OR REPLACE INTO migrate_purge (id, in_progress, files, backup, started_at, completed_at)
  VALUES (1, 1, '["app.db","secret_key","logs/.webssh-go/keyring-material"]', '', '2026-11-28T00:00:00Z', '');
END;`

// A Go archive from another installation whose database carries triggers
// is refused: a trigger on migrate_keyring would fire inside the restore
// and write a "purge in progress" entry that deletes app.db, secret_key
// and the keyring material at the next start. The live data stays as it was.
func TestRestoreRefusesArchiveWithTriggers(t *testing.T) {
	archiveA, _, _ := rotatedArchive(t)
	evil := rewriteGoArchive(t, archiveA, evilPurgeTrigger)
	hostB := migratedBesideLegacy(t)
	if out := runCLI(t, "backup", "restore", evil, "--confirm-offline"); out.Code == 0 {
		t.Fatalf("restore of an archive with triggers accepted: %+v", out)
	}
	for _, p := range []string{"app.db", "secret_key", "logs/.webssh-go/keyring-material"} {
		if _, err := os.Lstat(filepath.Join(hostB, p)); err != nil {
			t.Fatalf("%s after the refused restore: %v", p, err)
		}
	}
	db, err := store.Open(t.Context(), filepath.Join(hostB, "go", "webssh.db"), store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var n int
	err = db.Read(t.Context(), func(tx *store.Tx) error {
		return tx.QueryRowContext(t.Context(), `SELECT count(*) FROM sqlite_schema WHERE type IN ('trigger', 'view')`).Scan(&n)
	})
	if err != nil || n != 0 {
		t.Fatalf("triggers or views in the live database: %d, %v", n, err)
	}
}
