package architecture

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const modulePath = "github.com/bifrost0x/webssh"

// packagePatterns selects the module's Go code. "./..." is avoided because
// npm installs third-party Go files under node_modules; TestGoCodeLocation
// ensures nothing outside these patterns escapes the checks.
var packagePatterns = []string{"./cmd/...", "./internal/..."}

// targets are the release platforms. Dependency graphs are the union over
// all of them, so platform-specific imports are checked too.
var targets = []struct{ goos, goarch string }{
	{"linux", "amd64"}, {"linux", "arm64"}, {"windows", "amd64"},
	{"darwin", "amd64"}, {"darwin", "arm64"},
}

// processSyscalls are the system call numbers that create or replace a
// process. Referring to them is how Syscall and RawSyscall would start one.
var processSyscalls = []string{"SYS_EXECVE", "SYS_EXECVEAT", "SYS_FORK", "SYS_VFORK", "SYS_CLONE", "SYS_CLONE3"}

// processCalls lists identifiers that start processes, by import path.
// os/exec is rejected as an import; these are the remaining ways.
var processCalls = map[string][]string{
	"os":                       {"StartProcess"},
	"syscall":                  append([]string{"ForkExec", "Exec", "StartProcess", "CreateProcess", "CreateProcessAsUser"}, processSyscalls...),
	"golang.org/x/sys/unix":    append([]string{"Exec"}, processSyscalls...),
	"golang.org/x/sys/windows": {"CreateProcess", "CreateProcessAsUser", "ShellExecute"},
}

// goPackage is the subset of "go list -json" output the checks use.
type goPackage struct {
	ImportPath     string
	Dir            string
	Name           string
	Standard       bool
	GoFiles        []string
	CgoFiles       []string
	IgnoredGoFiles []string
	Imports        []string
	Module         *struct{ Path string }
	Error          *struct{ Err string }
}

// fileImports holds what the rules need from one Go source file.
type fileImports struct {
	name    string // base name
	imports []string
	// processCalls are references such as "os.StartProcess".
	processCalls []string
}

// sourcePackage is a package of the module with the imports of every
// non-test file, independent of build constraints.
type sourcePackage struct {
	rel   string // module-relative path, e.g. "internal/buildinfo"
	name  string
	files []fileImports
}

// depGraph is the import graph of the module's packages and all their
// dependencies, merged over all release platforms.
type depGraph struct {
	imports map[string][]string // import path -> direct imports
	module  map[string]string   // import path -> module path, external packages only
}

// runGo runs the go command outside any go.work file.
func runGo(ctx context.Context, dir string, env []string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "go", args...)
	cmd.Dir = dir
	cmd.Env = append(append(os.Environ(), "GOWORK=off"), env...)
	out, err := cmd.Output()
	if exitErr, ok := errors.AsType[*exec.ExitError](err); ok {
		return nil, fmt.Errorf("go %s: %w\n%s", strings.Join(args, " "), err, exitErr.Stderr)
	}
	if err != nil {
		return nil, fmt.Errorf("go %s: %w", strings.Join(args, " "), err)
	}
	return out, nil
}

// goOutput runs the go command in dir and returns its standard output.
func goOutput(t *testing.T, dir string, args ...string) []byte {
	t.Helper()
	out, err := runGo(t.Context(), dir, nil, args...)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// moduleRoot returns the directory of the main module.
func moduleRoot(t *testing.T) string {
	t.Helper()
	return strings.TrimSpace(string(goOutput(t, ".", "list", "-m", "-f", "{{.Dir}}")))
}

// readRepoFile reads a file given by its slash-separated path relative to
// the module root, without following paths out of the root.
func readRepoFile(t *testing.T, root, rel string) []byte {
	t.Helper()
	r, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	data, err := r.ReadFile(filepath.FromSlash(rel))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// decodeStream decodes the concatenated JSON objects that go list prints.
func decodeStream[T any](data []byte) ([]T, error) {
	var values []T
	dec := json.NewDecoder(bytes.NewReader(data))
	for {
		var v T
		err := dec.Decode(&v)
		if errors.Is(err, io.EOF) {
			return values, nil
		}
		if err != nil {
			return nil, fmt.Errorf("decode go list output: %w", err)
		}
		values = append(values, v)
	}
}

// loadPackages lists the module's packages with go list and parses every
// non-test file, including files excluded by build tags.
func loadPackages(t *testing.T, root string) []sourcePackage {
	t.Helper()
	args := append([]string{"list", "-e", "-json=ImportPath,Dir,Name,GoFiles,CgoFiles,IgnoredGoFiles,Error"}, packagePatterns...)
	listed, err := decodeStream[goPackage](goOutput(t, root, args...))
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) == 0 {
		t.Fatal("go list found no packages")
	}
	fset := token.NewFileSet()
	var pkgs []sourcePackage
	for _, p := range listed {
		if p.Error != nil {
			t.Fatalf("go list %s: %s", p.ImportPath, p.Error.Err)
		}
		rel, ok := relativeImport(p.ImportPath)
		if !ok {
			t.Fatalf("package %s is outside module %s", p.ImportPath, modulePath)
		}
		pkg := sourcePackage{rel: rel, name: p.Name}
		for _, name := range concat(p.GoFiles, p.CgoFiles, p.IgnoredGoFiles) {
			if strings.HasSuffix(name, "_test.go") {
				continue
			}
			fi, err := parseFile(fset, filepath.Join(p.Dir, name))
			if err != nil {
				t.Fatal(err)
			}
			pkg.files = append(pkg.files, fi)
		}
		pkgs = append(pkgs, pkg)
	}
	return pkgs
}

// graphOnce loads the dependency graph once per test binary; go list for
// five platforms is the slowest step of the suite.
var graphOnce = sync.OnceValues(func() (depGraph, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	out, err := runGo(ctx, ".", nil, "list", "-m", "-f", "{{.Dir}}")
	if err != nil {
		return depGraph{}, err
	}
	root := strings.TrimSpace(string(out))
	g := depGraph{imports: map[string][]string{}, module: map[string]string{}}
	for _, target := range targets {
		env := []string{"GOOS=" + target.goos, "GOARCH=" + target.goarch, "CGO_ENABLED=0"}
		args := append([]string{"list", "-e", "-deps", "-json=ImportPath,Standard,Imports,Module,Error"}, packagePatterns...)
		out, err := runGo(ctx, root, env, args...)
		if err != nil {
			return depGraph{}, err
		}
		pkgs, err := decodeStream[goPackage](out)
		if err != nil {
			return depGraph{}, err
		}
		for _, p := range pkgs {
			if p.Error != nil {
				return depGraph{}, fmt.Errorf("%s/%s: go list %s: %s", target.goos, target.goarch, p.ImportPath, p.Error.Err)
			}
			g.imports[p.ImportPath] = union(g.imports[p.ImportPath], p.Imports)
			if !p.Standard && p.Module != nil && p.Module.Path != modulePath {
				g.module[p.ImportPath] = p.Module.Path
			}
		}
	}
	return g, nil
})

func loadGraph(t *testing.T) depGraph {
	t.Helper()
	g, err := graphOnce()
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// externalClosure returns the packages reachable from importPath without
// passing through packages of this module, which are checked on their own.
func (g depGraph) externalClosure(importPath string) map[string]bool {
	seen := map[string]bool{}
	stack := []string{importPath}
	for len(stack) > 0 {
		p := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if seen[p] {
			continue
		}
		if _, own := relativeImport(p); own {
			continue
		}
		seen[p] = true
		stack = append(stack, g.imports[p]...)
	}
	return seen
}

// reachable returns all packages reachable from the roots, including them.
func (g depGraph) reachable(roots []string) map[string]bool {
	seen := map[string]bool{}
	stack := append([]string(nil), roots...)
	for len(stack) > 0 {
		p := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if !seen[p] {
			seen[p] = true
			stack = append(stack, g.imports[p]...)
		}
	}
	return seen
}

func union(a, b []string) []string {
	for _, v := range b {
		if !slices.Contains(a, v) {
			a = append(a, v)
		}
	}
	return a
}

func concat(lists ...[]string) []string {
	var all []string
	for _, l := range lists {
		all = append(all, l...)
	}
	return all
}

// parseFile reads the imports of a file and its references to
// process-starting identifiers.
func parseFile(fset *token.FileSet, file string) (fileImports, error) {
	f, err := parser.ParseFile(fset, file, nil, parser.SkipObjectResolution)
	if err != nil {
		return fileImports{}, fmt.Errorf("parse %s: %w", file, err)
	}
	fi := fileImports{name: filepath.Base(file)}
	local := map[string]string{} // local name -> import path
	for _, spec := range f.Imports {
		p, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			return fileImports{}, fmt.Errorf("%s: import path %s: %w", file, spec.Path.Value, err)
		}
		fi.imports = append(fi.imports, p)
		if _, watched := processCalls[p]; !watched {
			continue
		}
		name := path.Base(p)
		if spec.Name != nil {
			name = spec.Name.Name
		}
		if name == "." {
			fi.processCalls = append(fi.processCalls, "dot import of "+p)
			continue
		}
		local[name] = p
	}
	ast.Inspect(f, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if x, ok := sel.X.(*ast.Ident); ok {
			if p, ok := local[x.Name]; ok && slices.Contains(processCalls[p], sel.Sel.Name) {
				fi.processCalls = append(fi.processCalls, p+"."+sel.Sel.Name)
			}
		}
		return true
	})
	return fi, nil
}

// skippedDir reports whether a directory can hold no code of this module:
// tooling directories starting with ".", and directories of other package
// managers.
func skippedDir(name string) bool {
	return strings.HasPrefix(name, ".") || name == "vendor" || name == "node_modules"
}

// repoFiles are the Go files and nested go.mod files found by walkRepo,
// as slash-separated paths relative to the module root.
type repoFiles struct {
	goFiles    []string // without files under testdata
	nestedMods []string // directories with their own go.mod
}

func walkRepo(t *testing.T, root string) repoFiles {
	t.Helper()
	var found repoFiles
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == root {
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		switch {
		case d.IsDir() && skippedDir(d.Name()):
			return filepath.SkipDir
		case d.IsDir():
			return nil
		case d.Name() == "go.mod":
			found.nestedMods = append(found.nestedMods, path.Dir(rel))
		case strings.HasSuffix(d.Name(), ".go") && d.Type().IsRegular() && !underTestdata(rel):
			found.goFiles = append(found.goFiles, rel)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	return found
}

func underTestdata(rel string) bool {
	return slices.Contains(strings.Split(rel, "/"), "testdata")
}

// isStandardLibrary reports whether an import path belongs to the standard
// library: by Go convention its first element contains no dot. The cgo
// pseudo-package "C" matches too and is rejected separately.
func isStandardLibrary(importPath string) bool {
	first, _, _ := strings.Cut(importPath, "/")
	return !strings.Contains(first, ".")
}

// relativeImport returns the module-relative path of an import of this
// module.
func relativeImport(importPath string) (string, bool) {
	return strings.CutPrefix(importPath, modulePath+"/")
}

// isTransportFile reports whether a capability file may hold HTTP handlers
// or outbound HTTP clients: "http.go" or "http_<topic>.go".
func isTransportFile(name string) bool {
	name = path.Base(name)
	return name == "http.go" || strings.HasPrefix(name, "http_")
}
