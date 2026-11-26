package architecture

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// fork is an external module kept as a patched copy under third_party/. It
// stays its own module, bound to its upstream path by a replace directive
// in go.mod (M2 contracts, section Modules), so the import paths do not
// change and the patch can go upstream as it is. Its packages are outside
// this module's patterns; the fork's CI job runs its own test suite.
type fork struct {
	module string // upstream module path the fork replaces
	// deps are the only modules the fork's non-test packages may link.
	// Once a package of this module imports the fork, the same modules
	// need entries in allowed-modules.txt.
	deps []string
}

// forks maps fork directories, relative to the module root, to the fork.
var forks = map[string]fork{
	"third_party/go-smb2": {
		module: "github.com/hirochachacha/go-smb2/v2",
		deps: []string{
			"github.com/geoffgarside/ber", "github.com/go-crypt/x", "github.com/go-krb5/krb5", "github.com/go-krb5/x",
			"github.com/google/uuid", "github.com/pierrec/lz4/v4", "github.com/quic-go/quic-go",
			"golang.org/x/crypto", "golang.org/x/net", "golang.org/x/sys",
		},
	},
}

// goModReplace is one replace directive of "go mod edit -json".
type goModReplace struct {
	Old struct{ Path, Version string }
	New struct{ Path, Version string }
}

func isForkDir(rel string) bool {
	_, ok := forks[rel]
	return ok
}

// replaceViolations allows only replace directives that bind the module of
// a listed fork, without versions, to the fork's directory.
func replaceViolations(replaces []goModReplace, forks map[string]fork) []string {
	var problems []string
	for _, r := range replaces {
		where := fmt.Sprintf("replace %s => %s", r.Old.Path, r.New.Path)
		dir, local := strings.CutPrefix(r.New.Path, "./")
		f, known := forks[dir]
		switch {
		case !local || !known:
			problems = append(problems, where+": go.mod may only replace the module of a fork listed in forks_test.go, by ./<fork directory>")
		case r.Old.Path != f.module:
			problems = append(problems, fmt.Sprintf("%s: %s is the fork of %s", where, dir, f.module))
		case r.Old.Version != "" || r.New.Version != "":
			problems = append(problems, where+": a fork replace must not name versions")
		}
	}
	slices.Sort(problems)
	return problems
}

// forkLinkViolations compares the modules linked by a fork's non-test
// packages with its allowed dependencies, in both directions.
func forkLinkViolations(dir string, f fork, linked []string) []string {
	var problems []string
	for _, mod := range linked {
		if mod != f.module && !slices.Contains(f.deps, mod) {
			problems = append(problems, fmt.Sprintf("%s: links module %s, which is not among the fork's dependencies", dir, mod))
		}
	}
	for _, mod := range f.deps {
		if !slices.Contains(linked, mod) {
			problems = append(problems, fmt.Sprintf("%s: dependency %s is no longer linked; remove it from forks_test.go", dir, mod))
		}
	}
	slices.Sort(problems)
	return problems
}

// forkLinkedModules returns the modules reachable from the fork's non-test
// packages on any release platform.
func forkLinkedModules(t *testing.T, dir string) []string {
	t.Helper()
	var mods []string
	for _, target := range targets {
		env := []string{"GOOS=" + target.goos, "GOARCH=" + target.goarch, "CGO_ENABLED=0"}
		out, err := runGo(t.Context(), dir, env, "list", "-deps", "-f", "{{if not .Standard}}{{with .Module}}{{.Path}}{{end}}{{end}}", "./...")
		if err != nil {
			t.Fatal(err)
		}
		for line := range strings.Lines(string(out)) {
			if mod := strings.TrimSpace(line); mod != "" && !slices.Contains(mods, mod) {
				mods = append(mods, mod)
			}
		}
	}
	slices.Sort(mods)
	return mods
}

func TestForks(t *testing.T) {
	t.Parallel()
	root := moduleRoot(t)
	found := walkRepo(t, root).forks
	replaced := map[string]bool{}
	for _, r := range readGoMod(t).Replace {
		replaced[strings.TrimPrefix(r.New.Path, "./")] = true
	}
	for rel, f := range forks {
		t.Run(rel, func(t *testing.T) {
			t.Parallel()
			if !slices.Contains(found, rel) {
				t.Fatalf("%s: listed fork directory does not exist", rel)
			}
			dir := filepath.Join(root, filepath.FromSlash(rel))
			var mod goMod
			if err := json.Unmarshal(goOutput(t, dir, "mod", "edit", "-json"), &mod); err != nil {
				t.Fatal(err)
			}
			if mod.Module.Path != f.module {
				t.Errorf("%s/go.mod: module %q, want %q", rel, mod.Module.Path, f.module)
			}
			if !replaced[rel] {
				t.Errorf("%s: go.mod has no replace directive for the fork", rel)
			}
			if _, err := os.Stat(filepath.Join(dir, "LICENSE")); err != nil {
				t.Errorf("%s: the upstream license must stay with the fork: %v", rel, err)
			}
			for _, problem := range forkLinkViolations(rel, f, forkLinkedModules(t, dir)) {
				t.Error(problem)
			}
		})
	}
}

func TestReplaceViolations(t *testing.T) {
	t.Parallel()
	known := map[string]fork{"third_party/lib": {module: "example.com/lib/v2"}}
	replace := func(oldPath, oldVersion, newPath, newVersion string) goModReplace {
		var r goModReplace
		r.Old.Path, r.Old.Version, r.New.Path, r.New.Version = oldPath, oldVersion, newPath, newVersion
		return r
	}
	tests := []struct {
		name string
		r    goModReplace
		want string
	}{
		{name: "fork", r: replace("example.com/lib/v2", "", "./third_party/lib", "")},
		{name: "other module", r: replace("example.com/other", "", "./third_party/lib", ""), want: "is the fork of example.com/lib/v2"},
		{name: "unlisted directory", r: replace("example.com/lib/v2", "", "./third_party/other", ""), want: "may only replace"},
		{name: "path outside the module", r: replace("example.com/lib/v2", "", "../lib", ""), want: "may only replace"},
		{name: "module replacement", r: replace("example.com/lib/v2", "", "example.com/fork/v2", "v2.0.1"), want: "may only replace"},
		{name: "old version", r: replace("example.com/lib/v2", "v2.0.0", "./third_party/lib", ""), want: "must not name versions"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assertViolation(t, replaceViolations([]goModReplace{tt.r}, known), tt.want)
		})
	}
}

func TestForkLinkViolations(t *testing.T) {
	t.Parallel()
	f := fork{module: "example.com/lib/v2", deps: []string{"golang.org/x/crypto"}}
	tests := []struct {
		name   string
		linked []string
		want   string
	}{
		{name: "allowed", linked: []string{"example.com/lib/v2", "golang.org/x/crypto"}},
		{name: "extra module", linked: []string{"example.com/lib/v2", "golang.org/x/crypto", "github.com/quic-go/quic-go"}, want: "links module github.com/quic-go/quic-go"},
		{name: "stale dependency", linked: []string{"example.com/lib/v2"}, want: "no longer linked"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assertViolation(t, forkLinkViolations("third_party/lib", f, tt.linked), tt.want)
		})
	}
}
