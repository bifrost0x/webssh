//go:build linux

package legacy

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// A FIFO in place of a store is refused before it is opened. Reading it
// would block, or, with a writer present, return whatever the writer
// sends. The test provides such a writer, so a reader that skips the
// regular-file check gets the planted content instead of an error.
func TestReadLimitedRefusesFIFO(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	fifo := filepath.Join(dir, "profiles.json")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	writer, err := os.OpenFile(fifo, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.WriteString(`{"planted": true}`); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	done := make(chan error, 1)
	go func() {
		_, err := readLimited(root, "profiles.json", maxFileBytes)
		done <- err
	}()
	time.Sleep(50 * time.Millisecond)
	writer.Close() // lets a reader that opened the FIFO reach EOF
	if err := <-done; !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("err = %v, want ErrUnsafePath", err)
	}
}

// L3: hashFile checks the opened handle: a FIFO in place of a regular file
// neither blocks nor is read.
func TestHashFileRefusesFIFOOnTheHandle(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "f")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Lstat(path)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	done := make(chan error, 1)
	go func() { _, err := hashFile(root, "f", info); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a FIFO was hashed")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("hashFile blocked on a FIFO")
	}
}
