package remotecmd

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Quoting for a remote shell lives here only, so the rule cannot drift
// between capabilities (RC0-2): no other production file of the module
// spells the '"'"' escape of shlex.quote itself.
func TestQuotingHasOneHome(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	escape := `'"'"'`
	var found []string
	for _, dir := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() && d.Name() == "webassets" {
				return filepath.SkipDir
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			if filepath.Dir(path) == filepath.Join(root, "internal", "ssh", "remotecmd") {
				return nil
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if strings.Contains(string(raw), escape) {
				found = append(found, path)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(found) > 0 {
		t.Fatalf("shell quoting outside remotecmd: %v; use remotecmd.Quote or remotecmd.SingleQuote", found)
	}
}
