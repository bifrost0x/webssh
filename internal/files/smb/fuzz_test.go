package smb

import (
	"strings"
	"testing"
)

// FuzzSplitPath: an accepted path is the join of its components, each a
// valid component; nothing the share rules refuse gets through.
func FuzzSplitPath(f *testing.F) {
	for _, s := range []string{"/", "/a/b", "/a//b", "/CON", "/a/b.", "/a:b", "/ä/ö", "/" + strings.Repeat("p/", 130)} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, p string) {
		parts, err := splitPath(p)
		if err != nil {
			return
		}
		if len(parts) == 0 {
			if p != "/" {
				t.Fatalf("%q: no components", p)
			}
			return
		}
		if joinPath(parts) != p || len(parts) > maxComponents {
			t.Fatalf("%q: %q", p, parts)
		}
		for _, c := range parts {
			if !validComponent(c, maxComponent, true) || strings.ContainsAny(c, `/\`) {
				t.Fatalf("%q: component %q", p, c)
			}
		}
	})
}
