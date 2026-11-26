package keyring

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"

	"github.com/bifrost0x/webssh/internal/store"
)

// tree lists every path below dir with its type, to show that a refused
// call changed nothing.
func tree(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		out = append(out, rel+" "+d.Type().String())
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func put(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func present(t *testing.T, path string) bool {
	t.Helper()
	ok, err := exists(path)
	if err != nil {
		t.Fatal(err)
	}
	return ok
}

func TestCreateWithoutLegacyData(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	mp := pathsIn(dir)
	m, err := LoadOrCreateMaterial(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != MaterialSize || bytes.Equal(m, make([]byte, MaterialSize)) {
		t.Fatalf("material %x", m)
	}
	if present(t, filepath.Dir(mp.stateDir)) {
		t.Fatal("a fresh installation created logs/.webssh-go/")
	}
	checkMode(t, mp.goFile, 0o600)
	checkMode(t, mp.goDir, 0o700|fs.ModeDir)
	again, err := LoadOrCreateMaterial(dir, false)
	if err != nil || !bytes.Equal(again, m) {
		t.Fatalf("second load: %x, %v", again, err)
	}
	if present(t, mp.goTmp) {
		t.Fatal("temporary file left behind")
	}
}

func TestCreateWithLegacyData(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	mp := pathsIn(dir)
	m, err := LoadOrCreateMaterial(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	if present(t, mp.goFile) {
		t.Fatal("material written to go/ while legacy data exists")
	}
	checkMode(t, mp.stateFile, 0o600)
	checkMode(t, mp.stateDir, 0o700|fs.ModeDir)
	checkMode(t, filepath.Dir(mp.stateDir), 0o700|fs.ModeDir)
	// The flag only chooses where new material goes; existing material is
	// found in either place.
	again, err := LoadOrCreateMaterial(dir, false)
	if err != nil || !bytes.Equal(again, m) {
		t.Fatalf("second load: %x, %v", again, err)
	}
}

func checkMode(t *testing.T, path string, want fs.FileMode) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode() != want {
		t.Errorf("%s: mode %v, want %v", path, info.Mode(), want)
	}
}

// TestNeverRecreatedWhileADatabaseExists is condition I-23: missing
// material with a Go database is a stop, never new material.
func TestNeverRecreatedWhileADatabaseExists(t *testing.T) {
	t.Parallel()
	for _, suffix := range []string{"", "-wal", "-journal"} {
		for _, legacy := range []bool{false, true} {
			dir := t.TempDir()
			put(t, filepath.Join(dir, "go", "webssh.db"+suffix), []byte("x"))
			before := tree(t, dir)
			if _, err := LoadOrCreateMaterial(dir, legacy); !errors.Is(err, ErrMaterialMissing) {
				t.Fatalf("database%s, legacy %v: %v", suffix, legacy, err)
			}
			if after := tree(t, dir); !slices.Equal(before, after) {
				t.Fatalf("refused call changed the data directory: %v -> %v", before, after)
			}
		}
	}
}

// TestRealDatabaseWithoutMaterial uses a database written by the store and
// closed as at shutdown, then loses the material.
func TestRealDatabaseWithoutMaterial(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	m, err := LoadOrCreateMaterial(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(t.Context(), filepath.Join(dir, "go", "webssh.db"), store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(pathsIn(dir).goFile); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateMaterial(dir, false); !errors.Is(err, ErrMaterialMissing) {
		t.Fatalf("lost material: %v", err)
	}
	put(t, pathsIn(dir).goFile, m)
	if got, err := LoadOrCreateMaterial(dir, false); err != nil || !bytes.Equal(got, m) {
		t.Fatalf("restored material: %v", err)
	}
}

func TestUnusableMaterialStops(t *testing.T) {
	t.Parallel()
	tests := map[string]func(t *testing.T, mp materialPaths){
		"short file": func(t *testing.T, mp materialPaths) { put(t, mp.goFile, make([]byte, 31)) },
		"long file":  func(t *testing.T, mp materialPaths) { put(t, mp.stateFile, make([]byte, 33)) },
		"empty file": func(t *testing.T, mp materialPaths) { put(t, mp.goFile, nil) },
		"directory": func(t *testing.T, mp materialPaths) {
			if err := os.MkdirAll(mp.goFile, 0o700); err != nil {
				t.Fatal(err)
			}
		},
		"symlink": func(t *testing.T, mp materialPaths) {
			target := filepath.Join(filepath.Dir(mp.goDir), "elsewhere")
			put(t, target, make([]byte, MaterialSize))
			if err := os.MkdirAll(mp.goDir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, mp.goFile); err != nil {
				t.Skip(err)
			}
		},
		"go directory is a symlink": func(t *testing.T, mp materialPaths) {
			target := filepath.Join(filepath.Dir(mp.goDir), "real-go")
			put(t, filepath.Join(target, materialName), make([]byte, MaterialSize))
			if err := os.Symlink(target, mp.goDir); err != nil {
				t.Skip(err)
			}
		},
	}
	for name, setup := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			setup(t, pathsIn(dir))
			before := tree(t, dir)
			if _, err := LoadOrCreateMaterial(dir, false); !errors.Is(err, ErrMaterialFile) {
				t.Fatalf("err %v", err)
			}
			if after := tree(t, dir); !slices.Equal(before, after) {
				t.Fatalf("refused call changed the data directory: %v -> %v", before, after)
			}
		})
	}
}

func TestTwoCopies(t *testing.T) {
	t.Parallel()
	a, b := seq(0x00, 0x1f), seq(0x40, 0x5f)

	dir := t.TempDir()
	mp := pathsIn(dir)
	put(t, mp.goFile, a)
	put(t, mp.stateFile, b)
	before := tree(t, dir)
	if _, err := LoadOrCreateMaterial(dir, true); !errors.Is(err, ErrMaterialConflict) {
		t.Fatalf("differing copies: %v", err)
	}
	if after := tree(t, dir); !slices.Equal(before, after) {
		t.Fatal("refused call changed the data directory")
	}

	dir = t.TempDir()
	mp = pathsIn(dir)
	put(t, mp.goFile, a)
	put(t, mp.stateFile, a)
	put(t, mp.goTmp, a[:5])
	got, err := LoadOrCreateMaterial(dir, true)
	if err != nil || !bytes.Equal(got, a) {
		t.Fatalf("identical copies: %x, %v", got, err)
	}
	if present(t, mp.stateFile) || present(t, mp.goTmp) || !present(t, mp.goFile) {
		t.Fatal("interrupted move not completed")
	}
}

func TestMoveMaterialToGo(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	mp := pathsIn(dir)
	m, err := LoadOrCreateMaterial(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	r, err := Open(katSecret, m)
	if err != nil {
		t.Fatal(err)
	}
	other, err := Open(katSecret, seq(0x40, 0x5f))
	if err != nil {
		t.Fatal(err)
	}
	before := tree(t, dir)
	if err := MoveMaterialToGo(dir, other, func() error { return nil }); !errors.Is(err, ErrKeyMismatch) {
		t.Fatalf("move with another ring: %v", err)
	}
	if after := tree(t, dir); !slices.Equal(before, after) {
		t.Fatal("refused move changed the data directory")
	}

	boom := errors.New("database unavailable")
	if err := MoveMaterialToGo(dir, r, func() error { return boom }); !errors.Is(err, boom) {
		t.Fatalf("failed record: %v", err)
	}
	if !present(t, mp.stateFile) || !present(t, mp.goFile) {
		t.Fatal("a copy was removed although the move was not recorded")
	}

	records := 0
	if err := MoveMaterialToGo(dir, r, func() error { records++; return nil }); err != nil {
		t.Fatal(err)
	}
	if records != 1 || present(t, mp.stateFile) || present(t, mp.goTmp) {
		t.Fatalf("move not completed (records %d)", records)
	}
	checkMode(t, mp.goFile, 0o600)
	got, err := LoadOrCreateMaterial(dir, false)
	if err != nil || !bytes.Equal(got, m) {
		t.Fatalf("after the move: %v", err)
	}
	if err := MoveMaterialToGo(dir, r, func() error { records++; return nil }); err != nil || records != 2 {
		t.Fatalf("repeated move: %v", err)
	}
}

// TestMoveCrashPoints is I-25: from the state after every step of the move
// the next start finds exactly one consistent material, and calling the
// move again ends with the material only in go/.
func TestMoveCrashPoints(t *testing.T) {
	t.Parallel()
	m := seq(0x00, 0x1f)
	states := map[string]func(t *testing.T, mp materialPaths){
		"before step 1":        func(*testing.T, materialPaths) {},
		"partial temporary":    func(t *testing.T, mp materialPaths) { put(t, mp.goTmp, m[:7]) },
		"complete temporary":   func(t *testing.T, mp materialPaths) { put(t, mp.goTmp, m) },
		"after rename":         func(t *testing.T, mp materialPaths) { put(t, mp.goFile, m) },
		"after removing logs/": func(t *testing.T, mp materialPaths) { put(t, mp.goFile, m); _ = os.Remove(mp.stateFile) },
		"logs/ directory empty": func(t *testing.T, mp materialPaths) {
			put(t, mp.goFile, m)
			_ = os.Remove(mp.stateFile)
			_ = os.Remove(mp.stateDir)
		},
	}
	for name, crash := range states {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			mp := pathsIn(dir)
			put(t, filepath.Join(mp.goDir, databaseName), []byte("db"))
			put(t, mp.stateFile, m)
			crash(t, mp)
			got, err := LoadOrCreateMaterial(dir, false)
			if err != nil || !bytes.Equal(got, m) {
				t.Fatalf("start after crash: %x, %v", got, err)
			}
			if present(t, mp.goTmp) {
				t.Fatal("temporary copy left after start")
			}
			r, err := Open(katSecret, got)
			if err != nil {
				t.Fatal(err)
			}
			if err := MoveMaterialToGo(dir, r, func() error { return nil }); err != nil {
				t.Fatal(err)
			}
			if !present(t, mp.goFile) || present(t, mp.stateFile) {
				t.Fatal("material not only in go/ after completing the move")
			}
		})
	}
}
