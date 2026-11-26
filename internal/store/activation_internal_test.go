package store

import (
	"os"
	"path/filepath"
	"testing"
)

// The activation close refuses any side file still beside the database
// after SQLite closed it (migration specification, 5.2 step 10.2). SQLite
// itself removes its own, so the check is tested directly.
func TestOnlyDatabaseFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "webssh.db")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := onlyDatabaseFile(path); err != nil {
		t.Fatalf("clean: %v", err)
	}
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		if err := os.WriteFile(path+suffix, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := onlyDatabaseFile(path); err == nil {
			t.Errorf("%s accepted", suffix)
		}
		if err := os.Remove(path + suffix); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("elsewhere", path+"-wal"); err != nil {
		t.Fatal(err)
	}
	if err := onlyDatabaseFile(path); err == nil {
		t.Error("a dangling link accepted")
	}
}
