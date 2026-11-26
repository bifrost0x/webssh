package architecture

import (
	"errors"
	"go/ast"
	"go/build/constraint"
	"go/parser"
	"go/token"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// The end-to-end harness must never reach the release binary. Beyond the
// dependency check of TestReleaseBuildExcludesE2E, these tests make sure
// that check is not vacuous: the entry file exists, it is built only with
// the tag "e2e", and that build does reach the harness.

func TestE2EEntryFileIsTagged(t *testing.T) {
	t.Parallel()
	root := moduleRoot(t)
	src := readRepoFile(t, root, e2eEntryFile)
	f, err := parser.ParseFile(token.NewFileSet(), e2eEntryFile, src, parser.ParseComments|parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}
	expr, err := buildConstraint(f)
	if err != nil {
		t.Fatal(err)
	}
	// Every release target and the usual tags must leave the file out;
	// adding "e2e" must bring it in.
	for _, target := range targets {
		release := []string{target.goos, target.goarch, "gc", "unix"}
		if expr.Eval(func(tag string) bool { return slices.Contains(release, tag) }) {
			t.Errorf("%s is built for %s/%s without the tag e2e (constraint %q)", e2eEntryFile, target.goos, target.goarch, expr)
		}
		if !expr.Eval(func(tag string) bool { return tag == "e2e" || slices.Contains(release, tag) }) {
			t.Errorf("%s is not built for %s/%s with the tag e2e", e2eEntryFile, target.goos, target.goarch)
		}
	}
}

func buildConstraint(f *ast.File) (constraint.Expr, error) {
	for _, group := range f.Comments {
		if group.Pos() > f.Package {
			break
		}
		for _, c := range group.List {
			if constraint.IsGoBuild(c.Text) {
				return constraint.Parse(c.Text)
			}
		}
	}
	return nil, errMissingConstraint
}

var errMissingConstraint = errors.New(e2eEntryFile + " has no //go:build line")

func TestE2EBuildReachesHarness(t *testing.T) {
	t.Parallel()
	out := goOutput(t, moduleRoot(t), "list", "-tags", "e2e", "-deps", "-f", "{{.ImportPath}}", "./cmd/webssh")
	if !slices.Contains(strings.Fields(string(out)), modulePath+"/"+e2ePackage) {
		t.Fatalf("cmd/webssh built with -tags e2e does not reach %s; the release check would be vacuous", e2ePackage)
	}
}

// TestE2ESwitchesOnlyInEntryFile keeps the test-only variables
// (WEBSSH_E2E_*) out of every production file but the e2e entry file and
// the harness package, so no release code path can be switched by them.
func TestE2ESwitchesOnlyInEntryFile(t *testing.T) {
	t.Parallel()
	root := moduleRoot(t)
	fset := token.NewFileSet()
	for _, rel := range walkRepo(t, root).goFiles {
		if strings.HasSuffix(rel, "_test.go") || rel == e2eEntryFile || strings.HasPrefix(rel, e2ePackage+"/") {
			continue
		}
		f, err := parser.ParseFile(fset, rel, readRepoFile(t, root, rel), parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			if v, err := strconv.Unquote(lit.Value); err == nil && strings.Contains(v, "WEBSSH_E2E_") {
				t.Errorf("%s: mentions %q; only %s reads the test switches", fset.Position(lit.Pos()), v, e2eEntryFile)
			}
			return true
		})
	}
}
