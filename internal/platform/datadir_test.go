package platform

import (
	"errors"
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
