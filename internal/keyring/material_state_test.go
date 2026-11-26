package keyring

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// Condition F2 (C7): material that reached go/ beside legacy data moves
// to logs/.webssh-go/. From the state after every step of the move the
// next start finds one consistent material, and calling the move again
// ends with the material only under logs/.
func TestMoveMaterialToStateCrashPoints(t *testing.T) {
	t.Parallel()
	m := seq(0x40, 0x5f)
	states := map[string]func(t *testing.T, mp materialPaths){
		"before step 1":      func(*testing.T, materialPaths) {},
		"partial temporary":  func(t *testing.T, mp materialPaths) { put(t, mp.stateTmp, m[:5]) },
		"complete temporary": func(t *testing.T, mp materialPaths) { put(t, mp.stateTmp, m) },
		"after rename":       func(t *testing.T, mp materialPaths) { put(t, mp.stateFile, m) },
		"after removing go/": func(t *testing.T, mp materialPaths) { put(t, mp.stateFile, m); _ = os.Remove(mp.goFile) },
	}
	for name, crash := range states {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			mp := pathsIn(dir)
			put(t, filepath.Join(mp.goDir, databaseName), []byte("db"))
			put(t, mp.goFile, m)
			crash(t, mp)
			got, err := LoadOrCreateMaterial(dir, true)
			if err != nil || !bytes.Equal(got, m) {
				t.Fatalf("start after crash: %x, %v", got, err)
			}
			if present(t, mp.stateTmp) {
				t.Fatal("temporary copy left after start")
			}
			r, err := Open(katSecret, got)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := MoveMaterialToState(dir, r, r.KeyID()); err != nil {
				t.Fatal(err)
			}
			if present(t, mp.goFile) || !present(t, mp.stateFile) {
				t.Fatal("material not only under logs/ after completing the move")
			}
			checkMode(t, mp.stateFile, 0o600)
			if moved, err := MoveMaterialToState(dir, r, r.KeyID()); err != nil || moved {
				t.Fatalf("second call: %v, %v", moved, err)
			}
		})
	}
}

func TestMoveMaterialToStateRefuses(t *testing.T) {
	t.Parallel()
	m := seq(0x40, 0x5f)
	other := seq(0x60, 0x7f)
	r, err := Open(katSecret, m)
	if err != nil {
		t.Fatal(err)
	}
	wrong, err := Open(katSecret, other)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("wrong key id", func(t *testing.T) {
		dir := t.TempDir()
		mp := pathsIn(dir)
		put(t, mp.goFile, m)
		before := tree(t, dir)
		if _, err := MoveMaterialToState(dir, r, wrong.KeyID()); !errors.Is(err, ErrKeyMismatch) {
			t.Fatalf("err = %v", err)
		}
		if after := tree(t, dir); !slices.Equal(before, after) {
			t.Fatalf("changed: %v -> %v", before, after)
		}
	})
	t.Run("ring of other material", func(t *testing.T) {
		dir := t.TempDir()
		put(t, pathsIn(dir).goFile, m)
		if _, err := MoveMaterialToState(dir, wrong, ""); !errors.Is(err, ErrKeyMismatch) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("differing copies", func(t *testing.T) {
		dir := t.TempDir()
		mp := pathsIn(dir)
		put(t, mp.goFile, m)
		put(t, mp.stateFile, other)
		if _, err := MoveMaterialToState(dir, r, ""); !errors.Is(err, ErrMaterialConflict) {
			t.Fatalf("err = %v", err)
		}
		if !present(t, mp.goFile) || !present(t, mp.stateFile) {
			t.Fatal("a copy was removed")
		}
	})
	t.Run("nothing in go", func(t *testing.T) {
		dir := t.TempDir()
		put(t, pathsIn(dir).stateFile, m)
		if moved, err := MoveMaterialToState(dir, r, r.KeyID()); err != nil || moved {
			t.Fatalf("%v %v", moved, err)
		}
	})
}
