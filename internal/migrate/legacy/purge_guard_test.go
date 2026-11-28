package legacy

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/store"
)

// A purge entry only removes files the migration record lists as legacy
// files. An entry naming anything else (secret_key, the keyring material
// under logs/, a file the migration never saw) is not the result of a
// purge: the start stops without removing a file.
func TestInterruptedPurgeRemovesOnlyRecordedLegacyFiles(t *testing.T) {
	t.Parallel()
	for name, files := range map[string][]string{
		"secret_key":        {"app.db", "secret_key"},
		"keyring material":  {"logs/.webssh-go/" + keyring.MaterialName},
		"go directory":      {"go/" + keyring.DatabaseName},
		"unrecorded file":   {"operator-notes.txt"},
		"parent of datadir": {"../outside"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			o := migratedForPurge(t)
			l := mustLayout(t, o.DataDir)
			if err := os.WriteFile(filepath.Join(o.DataDir, "operator-notes.txt"), []byte("notes\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			db, err := store.Open(t.Context(), l.database, store.Options{})
			if err != nil {
				t.Fatal(err)
			}
			err = db.ApplyAll(t.Context(), RecordSchema())
			if err == nil {
				err = db.Write(t.Context(), func(tx *store.Tx) error {
					return writePurgeStart(t.Context(), tx, purgeEntry{InProgress: true, Files: files,
						StartedAt: time.Now().UTC().Format(time.RFC3339Nano)})
				})
			}
			if err := errors.Join(err, db.CloseForActivation(t.Context())); err != nil {
				t.Fatal(err)
			}
			_, err = startClosed(o)
			var se *StopError
			if !errors.As(err, &se) || se.State != S7 {
				t.Fatalf("start with a forged purge entry: %v", err)
			}
			for _, p := range []string{"app.db", "secret_key", "operator-notes.txt", "logs/.webssh-go/" + keyring.MaterialName,
				"go/" + keyring.DatabaseName} {
				if _, err := os.Lstat(filepath.Join(o.DataDir, filepath.FromSlash(p))); err != nil {
					t.Errorf("%s after the start: %v", p, err)
				}
			}
		})
	}
}
