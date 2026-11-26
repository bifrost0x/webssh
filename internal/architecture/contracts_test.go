package architecture

import (
	"bufio"
	"bytes"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
)

// contractsDoc is the human-readable M1 contract. Its catalog tables are
// checked against the code, so the document cannot drift.
const contractsDoc = "docs/architecture/m1-contracts.md"

// docColumn returns the first cell (without backticks) of every table row
// under the heading, and the second cell keyed by the first.
func docColumn(data []byte, heading string) (map[string]string, error) {
	rows := map[string]string{}
	inSection := false
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for n := 1; scanner.Scan(); n++ {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") {
			inSection = line == heading
			continue
		}
		if !inSection || !strings.HasPrefix(line, "| `") {
			continue
		}
		cells := strings.Split(strings.Trim(line, "|"), "|")
		if len(cells) < 2 {
			return nil, fmt.Errorf("line %d: want at least 2 columns", n)
		}
		key := strings.Trim(strings.TrimSpace(cells[0]), "`")
		if _, dup := rows[key]; dup {
			return nil, fmt.Errorf("line %d: duplicate row %s", n, key)
		}
		rows[key] = strings.Trim(strings.TrimSpace(cells[1]), "`")
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("no table rows under %q", heading)
	}
	return rows, scanner.Err()
}

// setDiff reports names on one side only.
func setDiff(what string, doc map[string]string, code []string) []string {
	var problems []string
	for _, name := range code {
		if _, ok := doc[name]; !ok {
			problems = append(problems, fmt.Sprintf("%s %q is in the code but not in %s", what, name, contractsDoc))
		}
	}
	for _, name := range slices.Sorted(maps.Keys(doc)) {
		if !slices.Contains(code, name) {
			problems = append(problems, fmt.Sprintf("%s %q is in %s but not in the code", what, name, contractsDoc))
		}
	}
	return problems
}

func TestContractDocumentation(t *testing.T) {
	t.Parallel()
	data := readRepoFile(t, moduleRoot(t), contractsDoc)

	codes, err := docColumn(data, "### Error codes")
	if err != nil {
		t.Fatal(err)
	}
	var codeNames []string
	for _, c := range fault.Codes() {
		codeNames = append(codeNames, string(c))
		if doc, ok := codes[string(c)]; ok && doc != fmt.Sprint(c.HTTPStatus()) {
			t.Errorf("error code %q: documented status %s, code says %d", c, doc, c.HTTPStatus())
		}
	}
	for _, p := range setDiff("error code", codes, codeNames) {
		t.Error(p)
	}

	types, err := docColumn(data, "### Message types")
	if err != nil {
		t.Fatal(err)
	}
	var typeNames []string
	for _, m := range protocol.V1() {
		typeNames = append(typeNames, m.Name)
		if _, mapped := packageMap[m.Owner]; !mapped {
			t.Errorf("message type %q: owner %s is not in the package map", m.Name, m.Owner)
		}
		if doc, ok := types[m.Name]; ok && doc != string(m.Dir) {
			t.Errorf("message type %q: documented direction %s, code says %s", m.Name, doc, m.Dir)
		}
	}
	for _, p := range setDiff("message type", types, typeNames) {
		t.Error(p)
	}

	actions, err := docColumn(data, "### Step-up actions")
	if err != nil {
		t.Fatal(err)
	}
	var actionNames []string
	for _, a := range principal.Actions() {
		actionNames = append(actionNames, string(a))
	}
	for _, p := range setDiff("step-up action", actions, actionNames) {
		t.Error(p)
	}
}

func TestReleaseBuildExcludesE2E(t *testing.T) {
	t.Parallel()
	g := loadGraph(t)
	if g.reachable([]string{modulePath + "/cmd/webssh"})[modulePath+"/"+e2ePackage] {
		t.Errorf("cmd/webssh depends on %s without the e2e build tag", e2ePackage)
	}
}

func TestDocColumn(t *testing.T) {
	t.Parallel()
	doc := []byte("# C\n\n### Error codes\n\n| Code | Status |\n|---|---|\n| `a` | 400 |\n| `b` | 500 |\n\n### Other\n\n| `c` | x |\n")
	got, err := docColumn(doc, "### Error codes")
	if err != nil || len(got) != 2 || got["a"] != "400" {
		t.Fatalf("docColumn = %v, %v", got, err)
	}
	if _, err := docColumn([]byte("| `a` | 1 |\n| `a` | 2 |\n"), "### X"); err == nil {
		t.Fatal("no error for a missing section")
	}
	if _, err := docColumn([]byte("### X\n| `a` | 1 |\n| `a` | 2 |\n"), "### X"); err == nil {
		t.Fatal("no error for a duplicate row")
	}
	problems := setDiff("x", map[string]string{"a": "", "b": ""}, []string{"a", "c"})
	if len(problems) != 2 {
		t.Fatalf("setDiff = %q", problems)
	}
}
