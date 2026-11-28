package audit

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// A link in place of the audit log is not followed: the logger refuses to
// start instead of appending to the link target (RC0-2).
func TestLoggerDoesNotFollowALink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, FileName)); err != nil {
		t.Fatal(err)
	}
	if l, err := Open(dir, Options{BackupCount: 1}); err == nil {
		_ = l.Close()
		t.Fatal("the logger opened a link as its log")
	}
}

// The reader opens each file without following a link and checks the
// opened file, so no link can be swapped in between check and open, and a
// FIFO does not block the scan.
func TestReaderOpensOnlyRegularFiles(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("secret line\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{link, fifo} {
		seen := 0
		if _, err := newestFirst(path, func([]byte) bool { seen++; return true }); err == nil || seen > 0 {
			t.Fatalf("%s: read %d lines, err %v", filepath.Base(path), seen, err)
		}
	}
	var lines []string
	if _, err := scanFiles([]string{link, fifo, target}, 10, func(b []byte) bool { lines = append(lines, string(b)); return true }); err != nil {
		t.Fatal(err)
	}
	if len(lines) != 1 || lines[0] != "secret line" {
		t.Fatalf("lines %q", lines)
	}
}
