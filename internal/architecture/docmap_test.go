package architecture

import (
	"bufio"
	"bytes"
	"fmt"
	"slices"
	"strings"
	"testing"
)

// packageMapDoc is the human-readable package map.
const packageMapDoc = "docs/architecture/go-package-map.md"

// docRow is one row of the "Packages" table.
type docRow struct {
	kind kind
	uses []string
}

// parseDocPackages reads the table under the "## Packages" heading. Its
// columns are package, kind, responsibility, may also import and step.
func parseDocPackages(data []byte) (map[string]docRow, error) {
	rows := map[string]docRow{}
	inSection := false
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for n := 1; scanner.Scan(); n++ {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "## ") {
			inSection = line == "## Packages"
			continue
		}
		if !inSection || !strings.HasPrefix(line, "| `") {
			continue
		}
		cells := strings.Split(strings.Trim(line, "|"), "|")
		if len(cells) != 5 {
			return nil, fmt.Errorf("line %d: want 5 columns, got %d", n, len(cells))
		}
		pkg := strings.Trim(strings.TrimSpace(cells[0]), "`")
		if _, dup := rows[pkg]; dup {
			return nil, fmt.Errorf("line %d: duplicate row for %s", n, pkg)
		}
		row := docRow{kind: kind(strings.TrimSpace(cells[1]))}
		for used := range strings.SplitSeq(cells[3], ",") {
			if used = strings.Trim(strings.TrimSpace(used), "`"); used != "" && used != "–" {
				row.uses = append(row.uses, used)
			}
		}
		rows[pkg] = row
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("no rows found under \"## Packages\"")
	}
	return rows, scanner.Err()
}

// docMapViolations compares the documented table with the package map.
func docMapViolations(doc map[string]docRow, m map[string]role) []string {
	var problems []string
	for pkg, row := range doc {
		r, ok := m[pkg]
		switch {
		case !ok:
			problems = append(problems, fmt.Sprintf("%s: documented but missing from the package map", pkg))
		case r.kind != row.kind:
			problems = append(problems, fmt.Sprintf("%s: documented as %s, package map says %s", pkg, row.kind, r.kind))
		case !slices.Equal(slices.Sorted(slices.Values(r.uses)), slices.Sorted(slices.Values(row.uses))):
			problems = append(problems, fmt.Sprintf("%s: documented imports %q differ from the package map %q", pkg, row.uses, r.uses))
		}
	}
	for pkg := range m {
		if _, ok := doc[pkg]; !ok {
			problems = append(problems, fmt.Sprintf("%s: in the package map but not documented in %s", pkg, packageMapDoc))
		}
	}
	slices.Sort(problems)
	return problems
}

func TestPackageMapDocumentation(t *testing.T) {
	t.Parallel()
	doc, err := parseDocPackages(readRepoFile(t, moduleRoot(t), packageMapDoc))
	if err != nil {
		t.Fatalf("%s: %v", packageMapDoc, err)
	}
	for _, problem := range docMapViolations(doc, packageMap) {
		t.Error(problem)
	}
}

func TestDocMapViolations(t *testing.T) {
	t.Parallel()
	const table = "# Map\n\n## Packages\n\n| Package | Kind | Responsibility | May also import | Step |\n|---|---|---|---|---|\n"
	m := map[string]role{
		"cmd/webssh":         {kind: entry},
		"internal/files":     {kind: capability},
		"internal/files/smb": {kind: capability, uses: []string{"internal/netpolicy"}},
		"internal/netpolicy": {kind: capability},
	}
	valid := table +
		"| `cmd/webssh` | entry | Wiring | – | G0 |\n" +
		"| `internal/files` | capability | Files | – | G4 |\n" +
		"| `internal/files/smb` | capability | SMB | `internal/netpolicy` | G5 |\n" +
		"| `internal/netpolicy` | capability | Targets | – | G3 |\n" +
		"\n## Other\n\n| `internal/ignored` | x | y | z | w |\n"
	tests := []struct {
		name, doc, want string
	}{
		{name: "matching", doc: valid},
		{name: "kind differs", doc: strings.Replace(valid, "| `internal/files` | capability", "| `internal/files` | edge", 1), want: "documented as edge"},
		{name: "uses differ", doc: strings.Replace(valid, "| `internal/netpolicy` | G5", "| – | G5", 1), want: "documented imports"},
		{name: "missing row", doc: strings.Replace(valid, "| `internal/netpolicy` | capability | Targets | – | G3 |\n", "", 1), want: "not documented"},
		{name: "extra row", doc: strings.Replace(valid, "\n## Other", "| `internal/extra` | capability | X | – | G9 |\n\n## Other", 1), want: "missing from the package map"},
		{name: "command kind differs", doc: strings.Replace(valid, "| `cmd/webssh` | entry", "| `cmd/webssh` | edge", 1), want: "documented as edge, package map says entry"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			doc, err := parseDocPackages([]byte(tt.doc))
			if err != nil {
				t.Fatal(err)
			}
			assertViolation(t, docMapViolations(doc, m), tt.want)
		})
	}
	t.Run("malformed row", func(t *testing.T) {
		t.Parallel()
		if _, err := parseDocPackages([]byte(table + "| `internal/a` | capability |\n")); err == nil {
			t.Fatal("want an error for a row with missing columns")
		}
	})
	t.Run("no table", func(t *testing.T) {
		t.Parallel()
		if _, err := parseDocPackages([]byte("# Map\n")); err == nil {
			t.Fatal("want an error without a Packages table")
		}
	})
}
