package commands

import (
	json "encoding/json/v2"
	"os"
	"testing"

	"github.com/bifrost0x/webssh/internal/fault"
)

// The differential tests replay testdata/oracle.json, which
// testdata/oracle.py records from app/command_set_manager.py and
// app/command_parameters.py (see there for how to refresh it).

type oracleCase struct {
	Kind       string         `json:"kind"`
	Steps      []any          `json:"steps"`
	UseSudo    bool           `json:"use_sudo"`
	Set        map[string]any `json:"set"`
	Values     any            `json:"values"`
	Text       string         `json:"text"`
	Validation *string        `json:"validation"`
	Resolved   *string        `json:"resolved"`
	Error      *string        `json:"error"`
}

func oracleIndex() commandIndex {
	idx := commandIndex{}
	for id, c := range map[string][2]string{
		"lib-plain": {"uptime", ""}, "lib-args": {"ls", "-la /tmp"},
		"lib-comment": {"echo hi", "# trailing"}, "lib-semi": {"echo a;", ""},
	} {
		idx[id] = map[string]any{"id": id, "command": c[0], "parameters": c[1]}
	}
	return idx
}

func loadOracle(t *testing.T) []oracleCase {
	t.Helper()
	raw, err := os.ReadFile("testdata/oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []oracleCase
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases) < 1000 {
		t.Fatalf("oracle holds %d cases", len(cases))
	}
	return cases
}

func message(err error) string {
	if err == nil {
		return ""
	}
	_, _, msg := fault.Status(err)
	return msg
}

func TestPythonOracle(t *testing.T) {
	t.Parallel()
	idx := oracleIndex()
	for i, c := range loadOracle(t) {
		var got, gotErr string
		switch c.Kind {
		case "chain":
			set := map[string]any{"name": "Golden ✓", "steps": c.Steps, "use_sudo": c.UseSudo, "parameters": []any{}}
			got, gotErr = resolveLoaded(set, idx, false)
		case "params":
			if v := checkParameterSet(c.Set); (c.Validation == nil) != (v == "") || (c.Validation != nil && *c.Validation != v) {
				t.Errorf("case %d: validation %q, Python %v", i, v, deref(c.Validation))
			}
			values, isObj := c.Values.(map[string]any)
			text, err := resolveWithValues(c.Set, values, isObj, c.UseSudo)
			got, gotErr = text, message(err)
		case "sudo":
			if got := prefixSudo(c.Text); c.Resolved == nil || got != *c.Resolved {
				t.Errorf("case %d: sudo(%q) = %q, Python %q", i, c.Text, got, deref(c.Resolved))
			}
			continue
		default:
			t.Fatalf("case %d: unknown kind %q", i, c.Kind)
		}
		if gotErr != deref(c.Error) || (c.Error == nil && got != deref(c.Resolved)) {
			t.Errorf("case %d (%s): Go %q / %q, Python %q / %q", i, c.Kind, got, gotErr, deref(c.Resolved), deref(c.Error))
		}
	}
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
