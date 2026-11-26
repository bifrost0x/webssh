package architecture

import (
	"bufio"
	"bytes"
	"fmt"
	"path"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// maxProductionLines is the size limit for non-test Go files (ADR 0003).
const maxProductionLines = 400

// sizeExceptionsFile lists production files allowed to exceed the limit.
const sizeExceptionsFile = "internal/architecture/size-exceptions.txt"

// forbiddenNames maps package or directory names to the reason they are
// rejected.
var forbiddenNames = map[string]string{
	"util":    "catch-all package; name the package after its capability",
	"utils":   "catch-all package; name the package after its capability",
	"common":  "catch-all package; name the package after its capability",
	"helper":  "catch-all package; name the package after its capability",
	"helpers": "catch-all package; name the package after its capability",
	"misc":    "catch-all package; name the package after its capability",
	// The repository's .gitignore, .dockerignore or hygiene check exclude
	// these names at any depth, so code in such a directory would be lost
	// or rejected.
	"data":     "excluded by repository ignore rules",
	"instance": "excluded by repository ignore rules",
	"secrets":  "excluded by repository ignore rules",
	"build":    "excluded by repository ignore rules",
	"dist":     "excluded by repository ignore rules",
	"plans":    "excluded by repository ignore rules",
	"reviews":  "excluded by repository ignore rules",
}

// sizeException is one entry of size-exceptions.txt.
type sizeException struct {
	maxLines int
	reason   string
}

// parseSizeExceptions reads lines of the form "<path> <max-lines> <reason>".
// Blank lines and lines starting with "#" are ignored.
func parseSizeExceptions(data []byte) (map[string]sizeException, error) {
	exceptions := map[string]sizeException{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for n := 1; scanner.Scan(); n++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			return nil, fmt.Errorf("line %d: want <path> <max-lines> <reason>", n)
		}
		limit, err := strconv.Atoi(fields[1])
		if err != nil || limit <= maxProductionLines {
			return nil, fmt.Errorf("line %d: max-lines must be a number above %d", n, maxProductionLines)
		}
		if _, dup := exceptions[fields[0]]; dup {
			return nil, fmt.Errorf("line %d: duplicate entry for %s", n, fields[0])
		}
		exceptions[fields[0]] = sizeException{maxLines: limit, reason: strings.Join(fields[2:], " ")}
	}
	return exceptions, scanner.Err()
}

// countLines counts lines the way editors and wc do for text files, also
// counting a final line without a trailing newline.
func countLines(data []byte) int {
	n := bytes.Count(data, []byte("\n"))
	if len(data) > 0 && data[len(data)-1] != '\n' {
		n++
	}
	return n
}

// sizeViolations checks production file sizes against the limit and the
// exception list. Stale exceptions are violations too, so the list only
// shrinks unless a reviewer accepts a new entry.
func sizeViolations(lines map[string]int, exceptions map[string]sizeException) []string {
	var problems []string
	for file, n := range lines {
		ex, excepted := exceptions[file]
		switch {
		case excepted && n > ex.maxLines:
			problems = append(problems, fmt.Sprintf("%s: %d lines, above its exception of %d", file, n, ex.maxLines))
		case excepted && n <= maxProductionLines:
			problems = append(problems, fmt.Sprintf("%s: %d lines; remove the stale size exception", file, n))
		case !excepted && n > maxProductionLines:
			problems = append(problems, fmt.Sprintf("%s: %d lines, above the limit of %d; split it by responsibility", file, n, maxProductionLines))
		}
	}
	for file := range exceptions {
		if _, ok := lines[file]; !ok {
			problems = append(problems, fmt.Sprintf("%s: size exception for a file that does not exist", file))
		}
	}
	slices.Sort(problems)
	return problems
}

// nameViolations checks every directory element of a module-relative
// package path and the declared package name.
func nameViolations(rel, name string) []string {
	var problems []string
	for _, element := range append(strings.Split(rel, "/"), name) {
		if reason, bad := forbiddenNames[element]; bad {
			problems = append(problems, fmt.Sprintf("%s: name %q is forbidden: %s", rel, element, reason))
		}
	}
	return slices.Compact(problems)
}

// locationViolation reports Go files outside cmd/ and internal/, and files
// in directories the go command ignores ("_" prefix), which would escape
// every check.
func locationViolation(file string) string {
	if !strings.HasPrefix(file, "cmd/") && !strings.HasPrefix(file, "internal/") {
		return file + ": Go code belongs under cmd/ or internal/"
	}
	for element := range strings.SplitSeq(path.Dir(file), "/") {
		if strings.HasPrefix(element, "_") {
			return file + ": the go command ignores directories starting with \"_\""
		}
	}
	return ""
}

// nestedModuleViolation reports go.mod files below the root. A nested
// module is outside every package pattern and every check; only test
// fixtures under testdata may have one.
func nestedModuleViolation(dir string) string {
	if dir == "." || underTestdata(dir+"/") {
		return ""
	}
	return dir + "/go.mod: nested modules are not allowed; the module is the repository"
}

func TestFileSizes(t *testing.T) {
	t.Parallel()
	root := moduleRoot(t)
	exceptions, err := parseSizeExceptions(readRepoFile(t, root, sizeExceptionsFile))
	if err != nil {
		t.Fatalf("%s: %v", sizeExceptionsFile, err)
	}
	lines := map[string]int{}
	for _, file := range walkRepo(t, root).goFiles {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		lines[file] = countLines(readRepoFile(t, root, file))
	}
	for _, problem := range sizeViolations(lines, exceptions) {
		t.Error(problem)
	}
}

func TestPackageNames(t *testing.T) {
	t.Parallel()
	for _, pkg := range loadPackages(t, moduleRoot(t)) {
		for _, problem := range nameViolations(pkg.rel, pkg.name) {
			t.Error(problem)
		}
	}
}

func TestGoCodeLocation(t *testing.T) {
	t.Parallel()
	found := walkRepo(t, moduleRoot(t))
	for _, file := range found.goFiles {
		if problem := locationViolation(file); problem != "" {
			t.Error(problem)
		}
	}
	for _, dir := range found.nestedMods {
		if problem := nestedModuleViolation(dir); problem != "" {
			t.Error(problem)
		}
	}
}

func TestCountLines(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   string
		want int
	}{
		{name: "empty", in: "", want: 0},
		{name: "one line", in: "package a\n", want: 1},
		{name: "no trailing newline", in: "package a\n\nfunc f() {}", want: 3},
		{name: "blank lines count", in: "\n\n\n", want: 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := countLines([]byte(tt.in)); got != tt.want {
				t.Errorf("countLines(%q) = %d, want %d", tt.in, got, tt.want)
			}
		})
	}
}

func TestParseSizeExceptions(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		in      string
		want    map[string]sizeException
		wantErr string
	}{
		{name: "comments only", in: "# header\n\n", want: map[string]sizeException{}},
		{
			name: "entry",
			in:   "internal/otp/vectors.go 900 RFC 6238 test vector table\n",
			want: map[string]sizeException{"internal/otp/vectors.go": {maxLines: 900, reason: "RFC 6238 test vector table"}},
		},
		{name: "missing reason", in: "internal/a/a.go 500\n", wantErr: "want <path> <max-lines> <reason>"},
		{name: "limit not above default", in: "internal/a/a.go 400 table\n", wantErr: "above 400"},
		{name: "limit not a number", in: "internal/a/a.go many table\n", wantErr: "must be a number"},
		{name: "duplicate", in: "internal/a/a.go 500 x\ninternal/a/a.go 600 y\n", wantErr: "duplicate"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := parseSizeExceptions([]byte(tt.in))
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want it to contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
			for k, v := range tt.want {
				if got[k] != v {
					t.Errorf("entry %s = %+v, want %+v", k, got[k], v)
				}
			}
		})
	}
}

func TestSizeViolations(t *testing.T) {
	t.Parallel()
	ex := map[string]sizeException{"internal/a/table.go": {maxLines: 600, reason: "vectors"}}
	tests := []struct {
		name  string
		lines map[string]int
		ex    map[string]sizeException
		want  string
	}{
		{name: "at limit", lines: map[string]int{"internal/a/a.go": 400}},
		{name: "above limit", lines: map[string]int{"internal/a/a.go": 401}, want: "above the limit of 400"},
		{name: "within exception", lines: map[string]int{"internal/a/table.go": 600}, ex: ex},
		{name: "above exception", lines: map[string]int{"internal/a/table.go": 601}, ex: ex, want: "above its exception of 600"},
		{name: "stale exception", lines: map[string]int{"internal/a/table.go": 120}, ex: ex, want: "stale size exception"},
		{name: "exception for missing file", lines: map[string]int{}, ex: ex, want: "does not exist"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assertViolation(t, sizeViolations(tt.lines, tt.ex), tt.want)
		})
	}
}

func TestNameViolations(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, rel, pkg, want string
	}{
		{name: "capability name", rel: "internal/files/smb", pkg: "smb"},
		{name: "util package", rel: "internal/util", pkg: "util", want: `"util" is forbidden`},
		{name: "nested helpers directory", rel: "internal/files/helpers", pkg: "helpers", want: `"helpers" is forbidden`},
		{name: "package name differs from directory", rel: "internal/files/paths", pkg: "common", want: `"common" is forbidden`},
		{name: "ignored directory", rel: "internal/data", pkg: "data", want: "excluded by repository ignore rules"},
		{name: "misc in the middle", rel: "internal/misc/x", pkg: "x", want: `"misc" is forbidden`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assertViolation(t, nameViolations(tt.rel, tt.pkg), tt.want)
		})
	}
}

func TestLocationViolation(t *testing.T) {
	t.Parallel()
	for _, file := range []string{"cmd/webssh/main.go", "internal/buildinfo/buildinfo.go"} {
		if got := locationViolation(file); got != "" {
			t.Errorf("locationViolation(%q) = %q, want none", file, got)
		}
	}
	for _, file := range []string{"main.go", "pkg/api/api.go", "tools/gen.go", "internal/_old/a.go"} {
		if got := locationViolation(file); got == "" {
			t.Errorf("locationViolation(%q) = none, want a violation", file)
		}
	}
}

func TestNestedModuleViolation(t *testing.T) {
	t.Parallel()
	tests := []struct{ dir, want string }{
		{dir: ".", want: ""},
		{dir: "internal/architecture/testdata/mod", want: ""},
		{dir: "internal/vault/sub", want: "nested modules are not allowed"},
		{dir: "tools", want: "nested modules are not allowed"},
	}
	for _, tt := range tests {
		got := nestedModuleViolation(tt.dir)
		if (tt.want == "") != (got == "") || !strings.Contains(got, tt.want) {
			t.Errorf("nestedModuleViolation(%q) = %q, want %q", tt.dir, got, tt.want)
		}
	}
}
