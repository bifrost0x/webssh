package architecture

import (
	"fmt"
	"go/token"
	"maps"
	"os"
	"path"
	"slices"
	"strings"
	"testing"
)

// execAllowed lists the packages that may start local processes. WebSSH
// runs commands on remote hosts over SSH only, so the list is empty; an
// entry needs a reviewed reason (ADR 0003).
var execAllowed = map[string]bool{}

// syscallAllowed lists the files that may import syscall directly. Entries
// for missing files fail TestExceptionListsAreCurrent.
var syscallAllowed = map[string]bool{
	// syscall.SIGTERM, the stop signal of docker stop; os has no portable
	// name for it.
	"cmd/webssh/signal.go": true,
	// Netlink route lookup for the tailnet rule (ADR 0010).
	"internal/netpolicy/route_linux.go": true,
	// The Go lock (flock), the read-only probes of Python's SQLite and
	// backup operation locks (F_GETLK, flock), free space (statfs) and the
	// inode for the legacy digest (migration specification 5.2, 5.3).
	"internal/migrate/legacy/host_linux.go": true,
}

// exceptions are the reviewed exception lists the import rules consult.
type exceptions struct {
	syscallFiles map[string]bool // module-relative file paths
	execPackages map[string]bool // module-relative package paths
}

var listedExceptions = exceptions{syscallFiles: syscallAllowed, execPackages: execAllowed}

// httpServerPackage is the only package that may expose debugging
// endpoints; expvar and net/http/pprof register on the default mux.
const httpServerPackage = "internal/httpapi"

var debugPackages = []string{"expvar", "net/rpc", "net/http/pprof"}

// transitiveTriggers are the packages whose presence anywhere below an
// import is reported. Subpackages of net/http are covered by net/http, so
// one dependency yields one message.
var transitiveTriggers = map[string]bool{
	"net/http": true, "html/template": true, "os/exec": true,
	"expvar": true, "net/rpc": true, "net/http/pprof": true,
}

// e2ePackage holds the end-to-end seed and test hooks. Only e2eEntryFile,
// built with the tag "e2e", may import it; TestReleaseBuildExcludesE2E
// checks that the untagged command does not reach it.
const (
	e2ePackage   = "internal/e2eseed"
	e2eEntryFile = "cmd/webssh/e2e.go"
)

// isTestSupport reports whether a package holds test doubles (named like
// net/http/httptest). Only test files and other test support packages may
// import one.
func isTestSupport(rel string) bool {
	return strings.HasSuffix(path.Base(rel), "test") && rel != "internal/architecture"
}

// closureFunc returns the external packages an import pulls in, including
// itself. A nil closure checks direct imports only.
type closureFunc func(importPath string) map[string]bool

// importViolations applies the import rules of ADR 0003 to the module's
// own and standard library imports, directly and through dependencies.
// External modules are checked by moduleImportViolations.
func importViolations(pkgs []sourcePackage, roles func(string) (role, bool), closure closureFunc, ex exceptions) []string {
	var problems []string
	for _, pkg := range pkgs {
		r, ok := roles(pkg.rel)
		if !ok {
			problems = append(problems, fmt.Sprintf("%s: package is not in the package map", pkg.rel))
			continue
		}
		for _, file := range pkg.files {
			where := pkg.rel + "/" + file.name
			for _, imp := range file.imports {
				for _, problem := range checkImport(pkg.rel, r, file.name, imp, roles, closure, ex) {
					problems = append(problems, where+": "+problem)
				}
			}
			if !ex.execPackages[pkg.rel] {
				for _, call := range file.processCalls {
					problems = append(problems, where+": uses "+call+", which starts a process; no package starts local processes without a listed reason")
				}
			}
		}
	}
	slices.Sort(problems)
	return slices.Compact(problems)
}

func checkImport(from string, r role, file, imp string, roles func(string) (role, bool), closure closureFunc, ex exceptions) []string {
	if to, own := relativeImport(imp); own {
		target, ok := roles(to)
		switch {
		case !ok:
			return []string{fmt.Sprintf("imports %s, which is not in the package map", to)}
		case !mayImport(from, r, to, target):
			return []string{fmt.Sprintf("%s package must not import %s package %s", r.kind, target.kind, to)}
		case isTestSupport(to) && !isTestSupport(from):
			return []string{fmt.Sprintf("imports test support package %s; only test files may", to)}
		case to == e2ePackage && from+"/"+file != e2eEntryFile:
			return []string{fmt.Sprintf("imports %s; only %s (build tag e2e) may", to, e2eEntryFile)}
		}
		return nil
	}
	var problems []string
	if imp == "C" {
		return []string{"imports \"C\"; cgo is not allowed (ADR 0001)"}
	}
	if isStandardLibrary(imp) {
		if problem := standardProblem(from, r, file, imp, true, ex); problem != "" {
			problems = append(problems, "imports "+imp+": "+problem)
		}
	}
	if closure == nil {
		return problems
	}
	deps := closure(imp)
	for _, dep := range slices.Sorted(maps.Keys(deps)) {
		if dep == imp || !transitiveTriggers[dep] {
			continue
		}
		if problem := standardProblem(from, r, file, dep, false, ex); problem != "" {
			problems = append(problems, fmt.Sprintf("imports %s, which depends on %s: %s", imp, dep, problem))
		}
	}
	return problems
}

// standardProblem returns why a standard library package may not be used
// in a file, or "". unsafe and syscall are checked only as direct imports,
// because most of the standard library uses them internally.
func standardProblem(from string, r role, file, std string, direct bool, ex exceptions) string {
	switch {
	case direct && std == "unsafe":
		return "unsafe is reserved for tier A dependencies"
	case direct && std == "syscall" && !ex.syscallFiles[from+"/"+file]:
		return "syscall is allowed only in listed files"
	case std == "os/exec" && !ex.execPackages[from]:
		return "no package starts local processes without a listed reason"
	case slices.Contains(debugPackages, std) && from != httpServerPackage:
		return "debug endpoints belong to " + httpServerPackage
	case isHTTPPackage(std) && r.kind == foundation:
		return "foundation packages do not use HTTP"
	case isHTTPPackage(std) && r.kind == capability && !isTransportFile(file):
		return "HTTP belongs in a transport file (http.go or http_*.go)"
	}
	return ""
}

func isHTTPPackage(imp string) bool {
	return imp == "net/http" || strings.HasPrefix(imp, "net/http/") || imp == "html/template"
}

func TestImportRules(t *testing.T) {
	t.Parallel()
	pkgs := loadPackages(t, moduleRoot(t))
	g := loadGraph(t)
	for _, problem := range importViolations(pkgs, roleOf, g.externalClosure, listedExceptions) {
		t.Error(problem)
	}
}

// staleExceptions reports exception entries whose file or package does not
// exist, so an exception is never granted before its code is reviewed.
func staleExceptions(ex exceptions, files, packages []string) []string {
	var problems []string
	for file := range ex.syscallFiles {
		if !slices.Contains(files, file) {
			problems = append(problems, file+": syscall exception for a file that does not exist")
		}
	}
	for pkg := range ex.execPackages {
		if !slices.Contains(packages, pkg) {
			problems = append(problems, pkg+": exec exception for a package that does not exist")
		}
	}
	slices.Sort(problems)
	return problems
}

func TestExceptionListsAreCurrent(t *testing.T) {
	t.Parallel()
	root := moduleRoot(t)
	var packages []string
	for _, pkg := range loadPackages(t, root) {
		packages = append(packages, pkg.rel)
	}
	for _, problem := range staleExceptions(listedExceptions, walkRepo(t, root).goFiles, packages) {
		t.Error(problem)
	}
}

func TestPackageMapIsConsistent(t *testing.T) {
	t.Parallel()
	for _, problem := range mapViolations(packageMap) {
		t.Error(problem)
	}
}

func TestImportViolations(t *testing.T) {
	t.Parallel()
	roles := map[string]role{
		"cmd/webssh":               {kind: entry},
		"internal/codec":           {kind: foundation},
		"internal/codec2":          {kind: foundation},
		"internal/files":           {kind: capability},
		"internal/files/smb":       {kind: capability, uses: []string{"internal/netpolicy"}},
		"internal/netpolicy":       {kind: capability},
		"internal/vault":           {kind: capability},
		"internal/httpapi":         {kind: edge},
		"internal/realtime":        {kind: edge},
		"internal/proxy":           {kind: edge, uses: []string{"internal/httpapi"}},
		"internal/codec/codectest": {kind: foundation},
		"internal/e2eseed":         {kind: edge},
	}
	lookup := func(rel string) (role, bool) { r, ok := roles[rel]; return r, ok }
	graph := depGraph{imports: map[string][]string{
		"expvar":                {"net/http", "encoding/json"},
		"net/rpc":               {"net/http"},
		"net/http":              {"crypto/tls"},
		"example.com/runner":    {"os/exec"},
		"example.com/codec":     {"encoding/json"},
		"example.com/webclient": {"net/http"},
	}}
	mod := func(rel string) string { return modulePath + "/" + rel }
	testExceptions := exceptions{
		syscallFiles: map[string]bool{"internal/netpolicy/route_test_fixture.go": true},
		execPackages: map[string]bool{},
	}
	tests := []struct {
		name  string
		pkg   string
		file  string
		imp   string
		calls []string
		want  string // substring of the only violation, empty for none
	}{
		{name: "entry imports edge", pkg: "cmd/webssh", file: "main.go", imp: mod("internal/httpapi")},
		{name: "foundation imports foundation", pkg: "internal/codec", file: "codec.go", imp: mod("internal/codec2")},
		{name: "foundation imports capability", pkg: "internal/codec", file: "codec.go", imp: mod("internal/vault"), want: "foundation package must not import capability"},
		{name: "capability imports foundation", pkg: "internal/vault", file: "service.go", imp: mod("internal/codec")},
		{name: "child imports parent", pkg: "internal/files/smb", file: "backend.go", imp: mod("internal/files")},
		{name: "parent imports child", pkg: "internal/files", file: "registry.go", imp: mod("internal/files/smb"), want: "capability package must not import capability"},
		{name: "declared cross capability", pkg: "internal/files/smb", file: "dial.go", imp: mod("internal/netpolicy")},
		{name: "undeclared cross capability", pkg: "internal/vault", file: "service.go", imp: mod("internal/netpolicy"), want: "must not import capability package internal/netpolicy"},
		{name: "capability imports httpapi", pkg: "internal/vault", file: "http.go", imp: mod("internal/httpapi"), want: "must not import edge"},
		{name: "capability imports realtime", pkg: "internal/vault", file: "realtime.go", imp: mod("internal/realtime"), want: "must not import edge"},
		{name: "edge imports capability", pkg: "internal/httpapi", file: "server.go", imp: mod("internal/vault")},
		{name: "edge imports undeclared edge", pkg: "internal/httpapi", file: "server.go", imp: mod("internal/realtime"), want: "edge package must not import edge"},
		{name: "edge imports declared edge", pkg: "internal/proxy", file: "proxy.go", imp: mod("internal/httpapi")},
		{name: "unmapped target", pkg: "internal/vault", file: "service.go", imp: mod("internal/util"), want: "not in the package map"},
		{name: "capability http in transport file", pkg: "internal/vault", file: "http.go", imp: "net/http"},
		{name: "capability http client file", pkg: "internal/vault", file: "http_client.go", imp: "net/http"},
		{name: "capability http in service file", pkg: "internal/vault", file: "service.go", imp: "net/http", want: "HTTP belongs in a transport file"},
		{name: "capability httputil in service file", pkg: "internal/vault", file: "service.go", imp: "net/http/httputil", want: "HTTP belongs in a transport file"},
		{name: "capability html template", pkg: "internal/vault", file: "page.go", imp: "html/template", want: "HTTP belongs in a transport file"},
		{name: "capability dependency pulls in http", pkg: "internal/vault", file: "service.go", imp: "example.com/webclient", want: "depends on net/http: HTTP belongs in a transport file"},
		{name: "capability dependency in transport file", pkg: "internal/vault", file: "http_client.go", imp: "example.com/webclient"},
		{name: "net/rpc in transport file", pkg: "internal/vault", file: "http.go", imp: "net/rpc", want: "imports net/rpc: debug endpoints belong to"},
		{name: "foundation http", pkg: "internal/codec", file: "http.go", imp: "net/http", want: "foundation packages do not use HTTP"},
		{name: "foundation dependency pulls in http", pkg: "internal/codec", file: "codec.go", imp: "example.com/webclient", want: "depends on net/http: foundation packages do not use HTTP"},
		{name: "expvar in another edge package", pkg: "internal/realtime", file: "ws.go", imp: "expvar", want: "imports expvar: debug endpoints belong to"},
		{name: "httpapi expvar", pkg: "internal/httpapi", file: "debug.go", imp: "expvar"},
		{name: "edge http", pkg: "internal/httpapi", file: "server.go", imp: "net/http"},
		{name: "unsafe", pkg: "internal/codec", file: "codec.go", imp: "unsafe", want: "reserved for tier A"},
		{name: "cgo", pkg: "internal/vault", file: "native.go", imp: "C", want: "cgo is not allowed"},
		{name: "syscall in unlisted file", pkg: "internal/vault", file: "service.go", imp: "syscall", want: "syscall is allowed only in listed files"},
		{name: "syscall in listed file", pkg: "internal/netpolicy", file: "route_test_fixture.go", imp: "syscall"},
		{name: "exec in capability", pkg: "internal/vault", file: "service.go", imp: "os/exec", want: "no package starts local processes"},
		{name: "exec in entry", pkg: "cmd/webssh", file: "main.go", imp: "os/exec", want: "no package starts local processes"},
		{name: "dependency that runs processes", pkg: "internal/codec", file: "codec.go", imp: "example.com/runner", want: "depends on os/exec"},
		{name: "harmless dependency", pkg: "internal/codec", file: "codec.go", imp: "example.com/codec"},
		{name: "os.StartProcess", pkg: "internal/vault", file: "service.go", imp: "os", calls: []string{"os.StartProcess"}, want: "uses os.StartProcess, which starts a process"},
		{name: "syscall.ForkExec in listed file", pkg: "internal/netpolicy", file: "route_test_fixture.go", imp: "syscall", calls: []string{"syscall.ForkExec"}, want: "uses syscall.ForkExec"},
		{name: "other standard library", pkg: "internal/codec", file: "codec.go", imp: "crypto/hmac"},
		{name: "production code imports test support", pkg: "internal/vault", file: "service.go", imp: mod("internal/codec/codectest"), want: "only test files may"},
		{name: "test support imports its parent", pkg: "internal/codec/codectest", file: "fake.go", imp: mod("internal/codec")},
		{name: "e2e seed from the tagged entry file", pkg: "cmd/webssh", file: "e2e.go", imp: mod("internal/e2eseed")},
		{name: "e2e seed from another entry file", pkg: "cmd/webssh", file: "main.go", imp: mod("internal/e2eseed"), want: "only cmd/webssh/e2e.go"},
		{name: "e2e seed from an edge package", pkg: "internal/httpapi", file: "server.go", imp: mod("internal/e2eseed"), want: "edge package must not import edge package internal/e2eseed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			pkgs := []sourcePackage{{rel: tt.pkg, files: []fileImports{{name: tt.file, imports: []string{tt.imp}, processCalls: tt.calls}}}}
			got := importViolations(pkgs, lookup, graph.externalClosure, testExceptions)
			assertViolation(t, got, tt.want)
		})
	}
	t.Run("unmapped package", func(t *testing.T) {
		t.Parallel()
		got := importViolations([]sourcePackage{{rel: "internal/helpers"}}, lookup, nil, testExceptions)
		assertViolation(t, got, "internal/helpers: package is not in the package map")
	})
	t.Run("unmapped command", func(t *testing.T) {
		t.Parallel()
		got := importViolations([]sourcePackage{{rel: "cmd/tool"}}, lookup, nil, testExceptions)
		assertViolation(t, got, "cmd/tool: package is not in the package map")
	})
}

func TestParseFileFindsProcessCalls(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	tests := []struct {
		name, src string
		want      []string
	}{
		{name: "os.StartProcess", src: "package a\nimport \"os\"\nvar _ = os.StartProcess\n", want: []string{"os.StartProcess"}},
		{name: "aliased syscall", src: "package a\nimport sc \"syscall\"\nfunc f() { sc.Exec(\"\", nil, nil) }\n", want: []string{"syscall.Exec"}},
		{name: "execve through Syscall", src: "package a\nimport \"syscall\"\nfunc f() { syscall.Syscall(syscall.SYS_EXECVE, 0, 0, 0) }\n", want: []string{"syscall.SYS_EXECVE"}},
		{name: "clone through x sys unix", src: "package a\nimport \"golang.org/x/sys/unix\"\nfunc f() { unix.RawSyscall(unix.SYS_CLONE3, 0, 0, 0) }\n", want: []string{"golang.org/x/sys/unix.SYS_CLONE3"}},
		{name: "harmless syscall use", src: "package a\nimport \"syscall\"\nfunc f() { syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, 0) }\n"},
		{name: "dot import", src: "package a\nimport . \"os\"\n", want: []string{"dot import of os"}},
		{name: "harmless os use", src: "package a\nimport \"os\"\nvar _ = os.Getenv\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			file := dir + "/" + strings.ReplaceAll(tt.name, " ", "_") + ".go"
			writeFile(t, file, tt.src)
			fi, err := parseFile(token.NewFileSet(), file)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(fi.processCalls, tt.want) {
				t.Errorf("processCalls = %q, want %q", fi.processCalls, tt.want)
			}
		})
	}
}

func TestMapViolations(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		m    map[string]role
		want string
	}{
		{name: "valid", m: map[string]role{"cmd/webssh": {kind: entry}, "internal/a": {kind: capability, uses: []string{"internal/b"}}, "internal/b": {kind: capability}}},
		{name: "outside internal and cmd", m: map[string]role{"pkg/a": {kind: foundation}}, want: "must be under internal/ or cmd/"},
		{name: "unknown kind", m: map[string]role{"internal/a": {kind: "service"}}, want: `unknown kind "service"`},
		{name: "entry outside cmd", m: map[string]role{"internal/a": {kind: entry}}, want: "entry packages live under cmd/"},
		{name: "command not entry", m: map[string]role{"cmd/tool": {kind: edge}}, want: "packages under cmd/ are entry"},
		{name: "foundation with uses", m: map[string]role{"internal/a": {kind: foundation, uses: []string{"internal/b"}}, "internal/b": {kind: capability}}, want: "declare no uses"},
		{name: "unknown use", m: map[string]role{"internal/a": {kind: capability, uses: []string{"internal/b"}}}, want: "uses unknown package"},
		{name: "self use", m: map[string]role{"internal/a": {kind: capability, uses: []string{"internal/a"}}}, want: "uses itself"},
		{name: "redundant foundation use", m: map[string]role{"internal/a": {kind: capability, uses: []string{"internal/b"}}, "internal/b": {kind: foundation}}, want: "always allowed"},
		{name: "capability uses edge", m: map[string]role{"internal/a": {kind: capability, uses: []string{"internal/b"}}, "internal/b": {kind: edge}}, want: "must not use edge package"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assertViolation(t, mapViolations(tt.m), tt.want)
		})
	}
}

// assertViolation expects exactly one violation containing want, or none
// when want is empty.
func assertViolation(t *testing.T, got []string, want string) {
	t.Helper()
	if want == "" {
		if len(got) != 0 {
			t.Errorf("violations = %q, want none", got)
		}
		return
	}
	if len(got) != 1 || !strings.Contains(got[0], want) {
		t.Errorf("violations = %q, want one containing %q", got, want)
	}
}

func writeFile(t *testing.T, name, content string) {
	t.Helper()
	if err := os.WriteFile(name, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestStaleExceptions(t *testing.T) {
	t.Parallel()
	ex := exceptions{
		syscallFiles: map[string]bool{"internal/netpolicy/route_linux.go": true},
		execPackages: map[string]bool{"internal/runner": true},
	}
	assertViolation(t, staleExceptions(ex, []string{"internal/netpolicy/route_linux.go"}, []string{"internal/runner"}), "")
	assertViolation(t, staleExceptions(ex, nil, []string{"internal/runner"}), "syscall exception for a file that does not exist")
	assertViolation(t, staleExceptions(ex, []string{"internal/netpolicy/route_linux.go"}, nil), "exec exception for a package that does not exist")
}
