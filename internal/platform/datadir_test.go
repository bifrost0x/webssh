package platform

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrepareDataDirRejectsRelativePath(t *testing.T) {
	t.Parallel()
	for _, path := range []string{"data", "./data", "../data", ""} {
		_, err := PrepareDataDir(path)
		if !errors.Is(err, ErrRelativeDataDir) {
			t.Errorf("PrepareDataDir(%q) = %v, want ErrRelativeDataDir", path, err)
		}
	}
}

func TestDataDirErrorMessage(t *testing.T) {
	t.Parallel()
	cause := errors.New("operation not permitted")
	err := &DataDirError{Path: "/app/data", Op: "restrict access", Err: cause, Hint: "chown it"}
	if got, want := err.Error(), "data directory /app/data: restrict access: operation not permitted; chown it"; got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
	if !errors.Is(err, cause) {
		t.Error("DataDirError does not unwrap to its cause")
	}
	noHint := &DataDirError{Path: "/x", Op: "resolve", Err: cause}
	if strings.Contains(noHint.Error(), ";") {
		t.Errorf("Error() without hint = %q", noHint.Error())
	}
}

// CheckDataDir accepts an existing absolute directory and refuses the
// rest, without creating anything.
func TestCheckDataDir(t *testing.T) {
	dir := t.TempDir()
	if err := CheckDataDir(dir); err != nil {
		t.Fatal(err)
	}
	if err := CheckDataDir("relative"); !errors.Is(err, ErrRelativeDataDir) {
		t.Errorf("relative: %v", err)
	}
	missing := filepath.Join(dir, "missing")
	if err := CheckDataDir(missing); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing: %v", err)
	}
	if _, err := os.Lstat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Error("CheckDataDir created the directory")
	}
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CheckDataDir(file); !errors.Is(err, errNotDirectory) {
		t.Errorf("file: %v", err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("entries %v", entries)
	}
}
