package architecture

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
)

// allowedModulesFile is the module allowlist of ADR 0004.
const allowedModulesFile = "internal/architecture/allowed-modules.txt"

// allowedModule is one entry of allowed-modules.txt.
type allowedModule struct {
	tier string
	// importers are module-relative package paths or path prefixes ending
	// in "/" that may import the module directly. Empty means the module
	// may only appear as an indirect dependency.
	importers []string
	reason    string
}

// goMod is the subset of "go mod edit -json" output the checks use.
type goMod struct {
	Module  struct{ Path string }
	Go      string
	Require []struct {
		Path     string
		Indirect bool
	}
	Replace []goModReplace
	Tool    []json.RawMessage
}

// parseAllowedModules reads lines of the form
// "<module> <tier A|B> <importers|-> <reason>".
func parseAllowedModules(data []byte) (map[string]allowedModule, error) {
	modules := map[string]allowedModule{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for n := 1; scanner.Scan(); n++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			return nil, fmt.Errorf("line %d: want <module> <tier> <importers|-> <reason>", n)
		}
		mod, tier := fields[0], fields[1]
		if _, dup := modules[mod]; dup {
			return nil, fmt.Errorf("line %d: duplicate entry for %s", n, mod)
		}
		isX := strings.HasPrefix(mod, "golang.org/x/")
		switch {
		case tier != "A" && tier != "B":
			return nil, fmt.Errorf("line %d: tier must be A or B", n)
		case tier == "A" && !isX:
			return nil, fmt.Errorf("line %d: tier A is reserved for golang.org/x modules", n)
		case tier == "B" && isX:
			return nil, fmt.Errorf("line %d: golang.org/x modules are tier A", n)
		}
		entry := allowedModule{tier: tier, reason: strings.Join(fields[3:], " ")}
		if fields[2] != "-" {
			entry.importers = strings.Split(fields[2], ",")
		}
		modules[mod] = entry
	}
	return modules, scanner.Err()
}

// owningModule returns the allowlisted module that provides importPath.
func owningModule(importPath string, allowed map[string]allowedModule) (string, bool) {
	best := ""
	for mod := range allowed {
		if (importPath == mod || strings.HasPrefix(importPath, mod+"/")) && len(mod) > len(best) {
			best = mod
		}
	}
	return best, best != ""
}

func importerAllowed(rel string, importers []string) bool {
	for _, allowed := range importers {
		if rel == allowed || (strings.HasSuffix(allowed, "/") && strings.HasPrefix(rel, allowed)) {
			return true
		}
	}
	return false
}

// moduleImportViolations checks that every external import comes from an
// allowlisted module and from a package allowed to use it directly.
func moduleImportViolations(pkgs []sourcePackage, allowed map[string]allowedModule) []string {
	var problems []string
	for _, pkg := range pkgs {
		for _, file := range pkg.files {
			for _, imp := range file.imports {
				if isStandardLibrary(imp) {
					continue
				}
				if _, own := relativeImport(imp); own {
					continue
				}
				where := pkg.rel + "/" + file.name
				mod, ok := owningModule(imp, allowed)
				switch {
				case !ok:
					problems = append(problems, fmt.Sprintf("%s: imports %s from a module that is not allowlisted", where, imp))
				case !importerAllowed(pkg.rel, allowed[mod].importers):
					problems = append(problems, fmt.Sprintf("%s: imports %s; %s may not use module %s directly", where, imp, pkg.rel, mod))
				}
			}
		}
	}
	slices.Sort(problems)
	return problems
}

// buildListViolations compares the allowlist with the modules reachable
// from the module's non-test packages and the direct requirements of go.mod in
// both directions. Modules that only appear in the module graph are not
// checked: they never reach a binary. Direct requirements are checked even
// when only tests use them, so test dependencies are reviewed too.
func buildListViolations(linked, direct []string, allowed map[string]allowedModule) []string {
	var problems []string
	used := union(slices.Clone(linked), direct)
	for _, mod := range used {
		if _, ok := allowed[mod]; ok {
			continue
		}
		reason := "is a direct requirement in go.mod"
		if slices.Contains(linked, mod) {
			reason = "is reachable from the module's packages"
		}
		problems = append(problems, fmt.Sprintf("module %s %s but not in %s", mod, reason, allowedModulesFile))
	}
	for mod := range allowed {
		if !slices.Contains(used, mod) {
			problems = append(problems, fmt.Sprintf("module %s is allowlisted but neither linked nor required directly; remove the entry", mod))
		}
	}
	slices.Sort(problems)
	return problems
}

// linkedModules returns the external modules reachable from any non-test
// package of the module on any release platform. All packages are roots,
// not only commands, so a package that is not wired into cmd/webssh yet is
// checked as soon as it exists.
func linkedModules(pkgs []sourcePackage, g depGraph) []string {
	var roots []string
	for _, pkg := range pkgs {
		roots = append(roots, modulePath+"/"+pkg.rel)
	}
	var mods []string
	for p := range g.reachable(roots) {
		if mod, ok := g.module[p]; ok && !slices.Contains(mods, mod) {
			mods = append(mods, mod)
		}
	}
	slices.Sort(mods)
	return mods
}

func readGoMod(t *testing.T) goMod {
	t.Helper()
	var mod goMod
	if err := json.Unmarshal(goOutput(t, moduleRoot(t), "mod", "edit", "-json"), &mod); err != nil {
		t.Fatal(err)
	}
	return mod
}

func loadAllowedModules(t *testing.T, root string) map[string]allowedModule {
	t.Helper()
	allowed, err := parseAllowedModules(readRepoFile(t, root, allowedModulesFile))
	if err != nil {
		t.Fatalf("%s: %v", allowedModulesFile, err)
	}
	return allowed
}

func TestGoModDirectives(t *testing.T) {
	t.Parallel()
	mod := readGoMod(t)
	if mod.Module.Path != modulePath {
		t.Errorf("module path = %q, want %q", mod.Module.Path, modulePath)
	}
	for _, problem := range replaceViolations(mod.Replace, forks) {
		t.Error(problem)
	}
	if len(mod.Tool) > 0 {
		t.Error("go.mod must not contain tool directives; CI installs pinned tools outside the module")
	}
}

func TestModuleAllowlist(t *testing.T) {
	t.Parallel()
	root := moduleRoot(t)
	allowed := loadAllowedModules(t, root)
	pkgs := loadPackages(t, root)
	var direct []string
	for _, req := range readGoMod(t).Require {
		if !req.Indirect {
			direct = append(direct, req.Path)
		}
	}
	for _, problem := range buildListViolations(linkedModules(pkgs, loadGraph(t)), direct, allowed) {
		t.Error(problem)
	}
	for _, problem := range moduleImportViolations(pkgs, allowed) {
		t.Error(problem)
	}
}

func TestParseAllowedModules(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		in      string
		wantErr string
	}{
		{name: "empty", in: "# none yet\n"},
		{name: "tier A", in: "golang.org/x/crypto A internal/ssh/,internal/auth/local SSH and bcrypt\n"},
		{name: "indirect only", in: "golang.org/x/sys A - required by x/crypto\n"},
		{name: "tier B", in: "github.com/pkg/sftp B internal/files/sftp SFTP protocol\n"},
		{name: "missing reason", in: "github.com/pkg/sftp B internal/files/sftp\n", wantErr: "want <module>"},
		{name: "unknown tier", in: "github.com/pkg/sftp C internal/files/sftp x\n", wantErr: "tier must be A or B"},
		{name: "tier A outside x", in: "github.com/pkg/sftp A internal/files/sftp x\n", wantErr: "reserved for golang.org/x"},
		{name: "x as tier B", in: "golang.org/x/sys B - x\n", wantErr: "are tier A"},
		{name: "duplicate", in: "golang.org/x/sys A - x\ngolang.org/x/sys A - y\n", wantErr: "duplicate"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := parseAllowedModules([]byte(tt.in))
			if tt.wantErr == "" && err != nil {
				t.Fatalf("err = %v, want none", err)
			}
			if tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)) {
				t.Fatalf("err = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestModuleImportViolations(t *testing.T) {
	t.Parallel()
	allowed := map[string]allowedModule{
		"golang.org/x/crypto": {tier: "A", importers: []string{"internal/ssh/", "internal/auth/local"}},
		"golang.org/x/sys":    {tier: "A"},
		"github.com/pkg/sftp": {tier: "B", importers: []string{"internal/files/sftp"}},
	}
	tests := []struct {
		name, pkg, imp, want string
	}{
		{name: "prefix importer", pkg: "internal/ssh/client", imp: "golang.org/x/crypto/ssh"},
		{name: "exact importer", pkg: "internal/auth/local", imp: "golang.org/x/crypto/bcrypt"},
		{name: "exact importer is not a prefix", pkg: "internal/auth/localx", imp: "golang.org/x/crypto/bcrypt", want: "may not use module golang.org/x/crypto"},
		{name: "wrong importer", pkg: "internal/vault", imp: "github.com/pkg/sftp", want: "may not use module github.com/pkg/sftp"},
		{name: "indirect only module", pkg: "internal/ssh/client", imp: "golang.org/x/sys/unix", want: "may not use module golang.org/x/sys"},
		{name: "not allowlisted", pkg: "internal/files/sftp", imp: "github.com/pkg/errors", want: "not allowlisted"},
		{name: "similar prefix is another module", pkg: "internal/files/sftp", imp: "github.com/pkg/sftpx", want: "not allowlisted"},
		{name: "standard library", pkg: "internal/vault", imp: "crypto/aes"},
		{name: "own module", pkg: "internal/vault", imp: modulePath + "/internal/fernet"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			pkgs := []sourcePackage{{rel: tt.pkg, files: []fileImports{{name: "a.go", imports: []string{tt.imp}}}}}
			assertViolation(t, moduleImportViolations(pkgs, allowed), tt.want)
		})
	}
}

func TestBuildListViolations(t *testing.T) {
	t.Parallel()
	allowed := map[string]allowedModule{"golang.org/x/sys": {tier: "A"}}
	tests := []struct {
		name           string
		linked, direct []string
		want           string
	}{
		{name: "linked and listed", linked: []string{"golang.org/x/sys"}},
		{name: "direct and listed", direct: []string{"golang.org/x/sys"}},
		{name: "linked but not listed", linked: []string{"golang.org/x/sys", "github.com/x/y"}, want: "github.com/x/y is reachable from the module's packages"},
		{name: "test-only direct requirement", linked: []string{"golang.org/x/sys"}, direct: []string{"github.com/x/assert"}, want: "github.com/x/assert is a direct requirement"},
		{name: "stale entry", want: "neither linked nor required directly"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assertViolation(t, buildListViolations(tt.linked, tt.direct, allowed), tt.want)
		})
	}
}

func TestLinkedModules(t *testing.T) {
	t.Parallel()
	g := depGraph{
		imports: map[string][]string{
			modulePath + "/cmd/webssh":     {modulePath + "/internal/store", "fmt"},
			modulePath + "/internal/store": {"example.com/sqlite/driver"},
			modulePath + "/internal/tool":  {"example.com/graphonly"},
			"example.com/sqlite/driver":    {"golang.org/x/sys/unix"},
		},
		module: map[string]string{
			"example.com/sqlite/driver": "example.com/sqlite",
			"golang.org/x/sys/unix":     "golang.org/x/sys",
			"example.com/graphonly":     "example.com/graphonly",
		},
	}
	// internal/tool is not wired into a command yet; its module counts.
	pkgs := []sourcePackage{{rel: "cmd/webssh"}, {rel: "internal/store"}, {rel: "internal/tool"}}
	got := linkedModules(pkgs, g)
	if want := []string{"example.com/graphonly", "example.com/sqlite", "golang.org/x/sys"}; !slices.Equal(got, want) {
		t.Errorf("linkedModules() = %q, want %q", got, want)
	}
}
