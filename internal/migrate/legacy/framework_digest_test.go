package legacy

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// flipInPlace changes one byte of a file without changing its size, and
// restores its modification time, as a write within one timestamp tick
// leaves it.
func flipInPlace(t *testing.T, path string, offset int) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 1)
	if _, err := f.ReadAt(b, int64(offset)); err != nil {
		t.Fatal(err)
	}
	b[0] ^= 0x01
	if _, err := f.WriteAt(b, int64(offset)); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
}

// ageAll sets every legacy file's modification time an hour back, so the
// racy-clean rule does not apply to them.
func ageAll(t *testing.T, dir string) {
	t.Helper()
	old := time.Now().Add(-time.Hour)
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() {
			return os.Chtimes(p, old, old)
		}
		return err
	})
}

// M1: app.db is always hashed: SQLite writes it in place with the same
// size, and a commit within one timestamp tick keeps the stat values.
func TestDigestAlwaysHashesAppDB(t *testing.T) {
	t.Parallel()
	dir := copyGolden(t)
	ageAll(t, dir)
	o := testOptions(t, dir)
	if _, err := startClosed(o); err != nil {
		t.Fatal(err)
	}
	flipInPlace(t, filepath.Join(dir, "app.db"), 200)
	if _, err := startClosed(o); stopCode(err) != CodeLegacyChanged {
		t.Fatalf("err = %v", err)
	}
}

// M1: the racy-clean rule: a file modified shortly before the recorded
// scan is hashed again even with unchanged stat values; an older one
// keeps its recorded hash (the fast path).
func TestDigestRacyClean(t *testing.T) {
	t.Parallel()
	dir := copyGolden(t)
	ageAll(t, dir)
	recent := filepath.Join(dir, "session_epoch")
	now := time.Now()
	if err := os.Chtimes(recent, now, now); err != nil {
		t.Fatal(err)
	}
	prev, err := scanSource(dir, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	flipInPlace(t, recent, 0)
	again, err := scanSource(dir, prev.Files, prev.ScannedAt)
	if err != nil || again.Digest() == prev.Digest() {
		t.Fatalf("a racy file kept its hash: %v", err)
	}
	// An old file with unchanged stat values keeps its recorded hash.
	stale := filepath.Join(dir, "known_hosts")
	base, _ := scanSource(dir, nil, 0)
	flipInPlace(t, stale, 0)
	fast, _ := scanSource(dir, base.Files, base.ScannedAt)
	if fast.Digest() != base.Digest() {
		t.Error("the fast path rehashed an old file with unchanged stat values")
	}
	// Same size, different modification time: hashed again.
	flipInPlace(t, stale, 1)
	older := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(stale, older, older); err != nil {
		t.Fatal(err)
	}
	if moved, _ := scanSource(dir, base.Files, base.ScannedAt); moved.Digest() == base.Digest() {
		t.Error("a changed modification time was missed")
	}
	// A changed size is always seen.
	if err := os.WriteFile(stale, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if grown, _ := scanSource(dir, base.Files, base.ScannedAt); grown.Digest() == base.Digest() {
		t.Error("a changed size was missed")
	}
}

// Digest 2 hashes every file again: a writer that changes a store in
// place with the same size and timestamp during the migration is caught.
func TestSecondDigestHashesEverything(t *testing.T) {
	t.Parallel()
	dir := copyGolden(t)
	ageAll(t, dir)
	o := testOptions(t, dir)
	o.checkpoint = func(p string) {
		if p == PointWritten {
			flipInPlace(t, filepath.Join(dir, "users", "user_3", "settings.json"), 3)
		}
	}
	if _, err := startClosed(o); stopCode(err) != CodeChangedDuring {
		t.Fatalf("err = %v", err)
	}
}
