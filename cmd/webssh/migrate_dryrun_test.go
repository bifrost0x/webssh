package main

import (
	"crypto/sha256"
	json "encoding/json/v2"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bifrost0x/webssh/internal/backup"
	"github.com/bifrost0x/webssh/internal/keyring"
)

// entryState is everything about one path below DATA_DIR that a dry run
// must leave alone: type and permission bits, size, content and the
// modification time, of directories too (an entry created and removed
// again changes the directory's time).
type entryState struct {
	mode  fs.FileMode
	size  int64
	sum   [32]byte
	mtime int64
}

func treeState(t *testing.T, dir string) map[string]entryState {
	t.Helper()
	out := map[string]entryState{}
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, path)
		e := entryState{mode: info.Mode(), mtime: info.ModTime().UnixNano()}
		if info.Mode().IsRegular() {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			e.size, e.sum = info.Size(), sha256.Sum256(data)
		}
		out[rel] = e
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// `webssh migrate --dry-run` leaves DATA_DIR byte for byte and entry for
// entry as it was, on every legacy DATA_DIR of the golden data set: it
// creates no keys/, logs/ or go/ directory, no lock file and no staging
// directory, and it narrows no mode. Its scratch database lives in
// TMPDIR and is gone afterwards.
func TestDryRunLeavesDataDirUntouched(t *testing.T) {
	for _, fx := range k10Fixtures {
		t.Run(fx.name, func(t *testing.T) {
			dir := extractGolden(t, fx.archive)
			env, _ := k10Env(t, dir)
			for k, v := range env {
				t.Setenv(k, v)
			}
			tmp := t.TempDir()
			t.Setenv("TMPDIR", tmp)
			before := treeState(t, dir)

			code, out, e := runIn(t, "", "webssh", "migrate", "--dry-run")
			if code != 0 {
				t.Fatalf("dry run: exit %d: %s", code, e)
			}
			var report struct {
				Result  string `json:"result"`
				Pending []any  `json:"pending"`
			}
			if err := json.Unmarshal([]byte(out), &report, json.RejectUnknownMembers(false)); err != nil || report.Result != "dry-run" {
				t.Fatalf("report %q: %v", out, err)
			}

			after := treeState(t, dir)
			for rel, b := range before {
				if a, ok := after[rel]; !ok {
					t.Errorf("%s removed", rel)
				} else if a != b {
					t.Errorf("%s changed: %+v, was %+v", rel, a, b)
				}
			}
			for rel := range after {
				if _, ok := before[rel]; !ok {
					t.Errorf("%s created", rel)
				}
			}
			if left, err := os.ReadDir(tmp); err != nil || len(left) != 0 {
				t.Errorf("TMPDIR after the dry run: %v %v", left, err)
			}
		})
	}
}

// A pending secret rotation would have to be completed first, which
// writes to DATA_DIR; the dry run refuses and leaves it to the start.
func TestDryRunRefusesPendingRotation(t *testing.T) {
	dir := extractGolden(t, k10Fixtures[1].archive)
	env, _ := k10Env(t, dir)
	for k, v := range env {
		t.Setenv(k, v)
	}
	if err := os.Mkdir(filepath.Join(dir, keyring.GoDirName), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, keyring.GoDirName, backup.PendingSecretName), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	before := treeState(t, dir)
	if code, _, e := runIn(t, "", "webssh", "migrate", "--dry-run"); code != 1 || !strings.Contains(e, "rotation of SECRET_KEY is pending") {
		t.Fatalf("dry run: %d %q", code, e)
	}
	if after := treeState(t, dir); !maps.Equal(after, before) {
		t.Error("the refused dry run changed DATA_DIR")
	}
}
