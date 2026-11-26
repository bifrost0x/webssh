package legacy

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/bifrost0x/webssh/internal/keyring"
)

func execLegacySQL(t *testing.T, dataDir string, statements ...string) {
	t.Helper()
	execSQL(t, filepath.Join(dataDir, "app.db"), statements...)
}

// assertStop checks that err is a STOP naming entity.
func assertStop(t *testing.T, err error, entity string) *StopError {
	t.Helper()
	se, ok := errors.AsType[*StopError](err)
	if !ok {
		t.Fatalf("want a STOP for %s, got %v", entity, err)
	}
	if se.Entity != entity {
		t.Fatalf("STOP names %q (%v), want %s", se.Entity, se, entity)
	}
	return se
}

// assertNoGoDatabase checks that a failed migration left no Go database
// and no staging directory behind.
func assertNoGoDatabase(t *testing.T, dataDir string) {
	t.Helper()
	goDir := filepath.Join(dataDir, keyring.GoDirName)
	if _, err := os.Stat(filepath.Join(goDir, keyring.DatabaseName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a Go database exists after a failed migration: %v", err)
	}
	staging, _ := filepath.Glob(filepath.Join(goDir, ".migration-*"))
	if len(staging) > 0 {
		t.Fatalf("staging left behind: %v", staging)
	}
}

func writeLegacyFile(t *testing.T, dataDir, rel, content string) {
	t.Helper()
	p := filepath.Join(dataDir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
