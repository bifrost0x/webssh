package store

import (
	"os"
	"path/filepath"
	"strings"
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

// CloseForActivation itself runs the check: a side file that appears
// after SQLite closed the database fails the close and is named. Not
// parallel: the test sets the package seam.
func TestCloseForActivationRefusesLeftoverSideFile(t *testing.T) {
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		path := filepath.Join(t.TempDir(), "webssh.db")
		db, err := Open(t.Context(), path, Options{})
		if err != nil {
			t.Fatal(err)
		}
		afterActivationClose = func(p string) {
			if err := os.WriteFile(p+suffix, []byte("x"), 0o600); err != nil {
				t.Error(err)
			}
		}
		t.Cleanup(func() { afterActivationClose = func(string) {} })
		err = db.CloseForActivation(t.Context())
		if err == nil || !strings.Contains(err.Error(), suffix) {
			t.Errorf("%s: %v", suffix, err)
		}
	}
}
