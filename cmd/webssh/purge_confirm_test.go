package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/bifrost0x/webssh/internal/backup"
	"github.com/bifrost0x/webssh/internal/migrate/legacy"
)

// The confirmation names every path the migration kept in place before
// it asks; --yes shows them without asking.
func TestConfirmPurgeListsKeptPaths(t *testing.T) {
	plan := legacy.PurgePlan{Files: 12, Kept: []legacy.KeptPath{{Path: "users/user_7", Reason: "user_directory_without_account", Files: 3}},
		KeptFiles: []string{"users/user_7/a", "users/user_7/b", "users/user_7/c"}}
	for _, tc := range []struct {
		stdin string
		yes   bool
		want  bool
	}{{"n\n", false, false}, {"\n", false, false}, {"y\n", false, true}, {"YES\n", false, true}, {"", true, true}} {
		var out bytes.Buffer
		got := confirmPurge(streams{stdin: strings.NewReader(tc.stdin), stdout: &out, stderr: &out}, plan, tc.yes)
		if got != tc.want || !strings.Contains(out.String(), "users/user_7 (user_directory_without_account, 3 files)") ||
			strings.Contains(out.String(), "[y/N]") == tc.yes {
			t.Errorf("%q yes=%v: %v %q", tc.stdin, tc.yes, got, out.String())
		}
	}
}

func TestHoldsLegacy(t *testing.T) {
	m := backup.Manifest{Files: []backup.File{{Name: backup.DatabaseName}, {Name: "data/users/user_7/a"}}}
	if err := holdsLegacy(m, []string{"users/user_7/a"}); err != nil {
		t.Fatal(err)
	}
	if err := holdsLegacy(m, []string{"users/user_7/a", "users/user_7/b"}); err == nil {
		t.Fatal("a missing kept file passed")
	}
}
