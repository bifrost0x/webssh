package httpapi

import (
	"flag"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

var updateAccess = flag.Bool("update-access", false, "rewrite testdata/route-access.txt from the route catalog")

// RS8-H01: the access level of every catalog route is pinned. A change
// of a level, above all a downgrade from admin or user to public, fails
// here and has to be made in the table on purpose. Most handlers check
// rights themselves as well, so a downgrade would otherwise stay green.
func TestRouteAccessTable(t *testing.T) {
	var lines []string
	seen := map[string]bool{}
	for _, rt := range catalogRoutes() {
		if seen[rt.pattern] {
			t.Errorf("%s is in the catalog twice", rt.pattern)
		}
		seen[rt.pattern] = true
		lines = append(lines, rt.pattern+"\t"+rt.access.String())
	}
	slices.Sort(lines)
	got := strings.Join(lines, "\n") + "\n"
	path := filepath.Join("testdata", "route-access.txt")
	if *updateAccess {
		if err := os.WriteFile(path, []byte(got), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got == string(want) {
		return
	}
	wantSet := map[string]bool{}
	for l := range strings.SplitSeq(strings.TrimSpace(string(want)), "\n") {
		wantSet[l] = true
	}
	for _, l := range lines {
		if !wantSet[l] {
			t.Errorf("not in the table: %s", l)
		}
		delete(wantSet, l)
	}
	for l := range wantSet {
		t.Errorf("in the table, not in the catalog: %s", l)
	}
}
