package legacy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bifrost0x/webssh/internal/keyring"
)

// goTree lists every path below go/ and logs/.webssh-go/ with its
// content hash, to show that a refused --replace moved nothing.
func goTree(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, base := range []string{"go", "logs/.webssh-go"} {
		_ = filepath.WalkDir(filepath.Join(dir, base), func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || filepath.Base(p) == lockName || strings.HasPrefix(filepath.Base(p), reportPrefix) {
				return nil
			}
			data, _ := os.ReadFile(p)
			rel, _ := filepath.Rel(dir, p)
			out[rel] = sha256Hex(string(data))
			return nil
		})
	}
	return out
}

func sameTree(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// H2: a wrong SECRET_KEY is named as such, and --replace checks it, the
// space and a running Python before it sets anything aside.
func TestReplaceChecksBeforeSettingAside(t *testing.T) {
	t.Parallel()
	dir := copyGolden(t)
	o := testOptions(t, dir)
	if _, err := startClosed(o); err != nil {
		t.Fatal(err)
	}
	wrong := o
	wrong.Secret += "x"
	if _, err := startClosed(wrong); stopCode(err) != CodeSecretMismatch || strings.Contains(err.Error(), "--replace") {
		t.Fatalf("start with a wrong secret: %v", err)
	}
	before := goTree(t, dir)
	if _, err := Replace(t.Context(), wrong); stopCode(err) != CodeSecretMismatch {
		t.Fatalf("replace with a wrong secret: %v", err)
	}
	if after := goTree(t, dir); !sameTree(before, after) {
		t.Fatalf("replace with a wrong secret moved files:\n%v\n%v", before, after)
	}

	// S9 with foreign material and too little space: nothing moves.
	material := filepath.Join(dir, "logs", ".webssh-go", keyring.MaterialName)
	foreign := make([]byte, keyring.MaterialSize)
	foreign[3] = 7
	if err := os.WriteFile(material, foreign, 0o600); err != nil {
		t.Fatal(err)
	}
	small := o
	small.freeSpace = func(string) (uint64, error) { return spaceMargin, nil }
	before = goTree(t, dir)
	if _, err := Replace(t.Context(), small); stopCode(err) != CodeNoSpace {
		t.Fatalf("replace without space: %v", err)
	}
	if after := goTree(t, dir); !sameTree(before, after) {
		t.Fatalf("replace without space moved files")
	}
	if _, err := startClosed(o); stopCode(err) != CodeKeyMaterial {
		t.Fatalf("still S9: %v", err)
	}
}

// M2: outside S9 the space for the copy of the old database counts.
func TestReplaceCountsTheCopyOfTheOldDatabase(t *testing.T) {
	t.Parallel()
	dir := copyGolden(t)
	o := testOptions(t, dir)
	if _, err := startClosed(o); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, "go", "webssh.db"))
	if err != nil {
		t.Fatal(err)
	}
	r := &run{o: o, l: mustLayout(t, dir)}
	r.listing, _ = scanSource(dir, nil, 0)
	need := uint64(3*r.listing.size("app.db")+r.listing.bytesBelow("users")) + spaceMargin // #nosec G115 -- test sizes
	tight := o
	tight.freeSpace = func(string) (uint64, error) { return need + uint64(info.Size()) - 1, nil } // #nosec G115 -- test sizes
	if _, err := Replace(t.Context(), tight); stopCode(err) != CodeNoSpace {
		t.Fatalf("err = %v", err)
	}
	if m, _ := filepath.Glob(filepath.Join(dir, "go", "replaced-*")); len(m) != 0 {
		t.Fatalf("set aside before the space check: %v", m)
	}
}

// I-22 and the decision on 5.4: in S9 material that does not match the
// moved database goes below logs/.webssh-go/replaced-<UTC>/, never into go/.
// Of two differing copies, the one matching the database stays in place.
func TestReplaceInS9KeepsMaterialOutOfGo(t *testing.T) {
	t.Parallel()
	dir := copyGolden(t)
	o := testOptions(t, dir)
	if _, err := startClosed(o); err != nil {
		t.Fatal(err)
	}
	inState := filepath.Join(dir, "logs", ".webssh-go", keyring.MaterialName)
	good, _ := os.ReadFile(inState)
	foreign := make([]byte, keyring.MaterialSize)
	foreign[5] = 9
	if err := os.WriteFile(filepath.Join(dir, "go", keyring.MaterialName), foreign, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := startClosed(o); stopCode(err) != CodeKeyMaterial {
		t.Fatalf("two differing copies: %v", err)
	}
	res, err := Replace(t.Context(), o)
	if err != nil {
		t.Fatal(err)
	}
	if m, _ := filepath.Glob(filepath.Join(dir, "go", "replaced-*", "keyring-material*")); len(m) != 0 {
		t.Fatalf("material in go/: %v", m)
	}
	moved, _ := filepath.Glob(filepath.Join(dir, "logs", ".webssh-go", "replaced-*", "keyring-material-go"))
	if len(moved) != 1 {
		t.Fatalf("foreign material not set aside: %v", moved)
	}
	if got, _ := os.ReadFile(moved[0]); string(got) != string(foreign) {
		t.Error("moved material changed")
	}
	if got, _ := os.ReadFile(inState); string(got) != string(good) {
		t.Error("the matching material was not kept")
	}
	if res.Database == "" {
		t.Error("old database not named")
	}
	if st, err := startClosed(o); err != nil || st.State != S2 {
		t.Fatalf("%+v, %v", st, err)
	}
}

// --replace needs a complete legacy source; without one (S5, or S9 with
// the legacy data gone) it refuses and moves nothing.
func TestReplaceWithoutLegacyMovesNothing(t *testing.T) {
	t.Parallel()
	dir := copyGolden(t)
	o := testOptions(t, dir)
	if _, err := startClosed(o); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "app.db")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "logs", ".webssh-go", keyring.MaterialName)); err != nil {
		t.Fatal(err)
	}
	before := goTree(t, dir)
	if _, err := Replace(t.Context(), o); stopCode(err) != CodeReplaceNoLegacy {
		t.Fatalf("err = %v", err)
	}
	if after := goTree(t, dir); !sameTree(before, after) {
		t.Fatal("replace without legacy data moved files")
	}
}

// L4: the S1a message names a database --replace set aside earlier.
func TestGoDataMissingNamesReplacedDatabase(t *testing.T) {
	t.Parallel()
	dir := copyGolden(t)
	o := testOptions(t, dir)
	if _, err := startClosed(o); err != nil {
		t.Fatal(err)
	}
	kept := filepath.Join(dir, "go", "replaced-20261126T000000.000000000Z")
	if err := os.Mkdir(kept, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(dir, "go", "webssh.db"), filepath.Join(kept, "webssh.db")); err != nil {
		t.Fatal(err)
	}
	if _, err := startClosed(o); stopCode(err) != CodeGoDataMissing || !strings.Contains(err.Error(), kept) {
		t.Fatalf("err = %v", err)
	}
}
