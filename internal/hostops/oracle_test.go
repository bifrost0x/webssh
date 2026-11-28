package hostops

import (
	"encoding/hex"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// The oracle is recorded from the Python release by testdata/oracle.py.

type oracleOutcome struct {
	OK    jsontext.Value `json:"ok"`
	Error string         `json:"error"`
}

type oracleCorpus struct {
	Scripts  map[string]string   `json:"scripts"`
	Actions  map[string][]string `json:"actions"`
	Commands []struct {
		Action string         `json:"action"`
		Target jsontext.Value `json:"target"`
		Sudo   jsontext.Value `json:"sudo"`
		oracleOutcome
	} `json:"commands"`
	Stats     []oracleText `json:"stats"`
	Inventory []oracleText `json:"inventory"`
	Processes []oracleText `json:"processes"`
	Logs      []struct {
		Output      string    `json:"output"`
		ErrorOutput string    `json:"error_output"`
		OK          [2]string `json:"ok"`
	} `json:"logs"`
	Display []struct {
		Input string `json:"input"`
		OK    string `json:"ok"`
	} `json:"display"`
	Herdr []struct {
		Input string `json:"input"`
		oracleOutcome
	} `json:"herdr"`
	HerdrFailure []struct {
		Status int    `json:"status"`
		Stderr string `json:"stderr"`
		OK     string `json:"ok"`
	} `json:"herdr_failure"`
}

type oracleText struct {
	Input string `json:"input"`
	oracleOutcome
}

func readOracle(t *testing.T) oracleCorpus { return readOracleF(t) }

func readOracleF(t testing.TB) oracleCorpus {
	t.Helper()
	raw, err := os.ReadFile("testdata/oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var c oracleCorpus
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	return c
}

func hexDecode(s string) ([]byte, error) { return hex.DecodeString(s) }

// sameJSON compares two JSON documents by value; numbers compare as
// float64, so 3.0 from Python equals 3 from Go.
func sameJSON(t *testing.T, want jsontext.Value, got any) bool {
	t.Helper()
	g, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	var a, b any
	if err := json.Unmarshal(want, &a); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(g, &b); err != nil {
		t.Fatal(err)
	}
	return reflect.DeepEqual(a, b)
}

func codeOf(err error) string {
	if oe, ok := err.(*opError); ok {
		return oe.code
	}
	if err != nil {
		return "value_error"
	}
	return ""
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// inventoryFirstRowFix is the one declared change to a collector program
// of the Python release (fix): its awk programs for systemd units and
// Docker containers indexed their arrays by stored before it was set, so
// the first row was stored under "" and the END loop, counting from 0,
// emitted an empty row in its place. Both programs now start stored at 0.
var inventoryFirstRowFix = []struct{ before, after string }{
	{"    systemd_units)\n      awk '\n        NF {", "    systemd_units)\n      awk '\n        BEGIN { stored = 0 }\n        NF {"},
	{"    docker_containers)\n      awk '\n        NF && stored < 50 {", "    docker_containers)\n      awk '\n        BEGIN { stored = 0 }\n        NF && stored < 50 {"},
}

func TestOracleProgramsAreThoseOfPython(t *testing.T) {
	c := readOracle(t)
	for _, fix := range inventoryFirstRowFix {
		if strings.Count(c.Scripts["runtime_inventory"], fix.before) != 1 {
			t.Fatalf("the Python inventory program no longer holds %q", fix.before)
		}
		c.Scripts["runtime_inventory"] = strings.Replace(c.Scripts["runtime_inventory"], fix.before, fix.after, 1)
	}
	for name, got := range map[string]string{
		"insights_stats": insightsStatsProgram, "insights_diagnostics": insightsDiagnosticsProgram,
		"runtime_inventory": inventoryProgram, "herdr_probe": HerdrProbeCommand,
		"herdr_snapshot": herdrSnapshotCommand, "herdr_session": HerdrSessionCommand,
	} {
		if got != c.Scripts[name] {
			t.Errorf("%s differs from the Python release", name)
		}
	}
	if !slices.Equal(c.Actions["read"], readActions) || !slices.Equal(c.Actions["write"], writeActions) {
		t.Errorf("actions %v %v", readActions, writeActions)
	}
}

// pythonLine is the command line of the Python release for c: the process
// programs were passed with "python3 -c", here they travel on stdin.
func pythonLine(c opCommand, python string) string {
	for _, program := range []string{c.Stdin, strings.TrimSuffix(c.Stdin, "\n")} {
		quoted := "'" + strings.ReplaceAll(program, "'", `'"'"'`) + "'"
		python = strings.Replace(python, "python3 -c "+quoted, "python3 -", 1)
	}
	return python
}

func TestOracleCommands(t *testing.T) {
	for _, tc := range readOracle(t).Commands {
		req := opRequest{"action": jsontext.Value(`"` + tc.Action + `"`), "target": tc.Target, "use_sudo": tc.Sudo}
		_, cmd, err := req.command(append(slices.Clone(readActions), writeActions...))
		if got := codeOf(err); got != tc.Error {
			t.Errorf("%s %s: error %q, Python %q", tc.Action, tc.Target, got, tc.Error)
			continue
		}
		if err != nil {
			continue
		}
		var want string
		if json.Unmarshal(tc.OK, &want) != nil {
			t.Fatal(tc.OK)
		}
		if got := cmd.Line; got != pythonLine(cmd, want) {
			t.Errorf("%s %s:\n got %q\nwant %q", tc.Action, tc.Target, got, want)
		}
		if cmd.Stdin == "" && cmd.Text() != want {
			t.Errorf("%s: review text %q", tc.Action, cmd.Text())
		}
	}
}

func TestOracleStats(t *testing.T) {
	for i, tc := range readOracle(t).Stats {
		st, err := ParseStats(tc.Input)
		switch {
		case tc.Error != "":
			if err == nil {
				t.Errorf("case %d: parsed %+v, Python refused", i, st)
			}
		case err != nil:
			t.Errorf("case %d: %v, Python parsed %s", i, err, tc.OK)
		case !sameJSON(t, tc.OK, st):
			g, _ := json.Marshal(st)
			t.Errorf("case %d:\n got %s\nwant %s", i, g, tc.OK)
		}
	}
}

func TestOracleInventory(t *testing.T) {
	for i, tc := range readOracle(t).Inventory {
		inv, err := ParseInventory(tc.Input)
		if err != nil || tc.Error != "" {
			t.Errorf("case %d: %v / %q", i, err, tc.Error)
			continue
		}
		if !sameJSON(t, tc.OK, inv) {
			g, _ := json.Marshal(inv)
			t.Errorf("case %d:\n got %s\nwant %s", i, g, tc.OK)
		}
	}
}

func TestOracleProcessList(t *testing.T) {
	for i, tc := range readOracle(t).Processes {
		rows, err := parseProcessList(tc.Input)
		if got := codeOf(err); got != tc.Error {
			t.Errorf("case %d %q: error %q, Python %q", i, tc.Input, got, tc.Error)
			continue
		}
		if err == nil && !sameJSON(t, tc.OK, rows) {
			g, _ := json.Marshal(rows)
			t.Errorf("case %d:\n got %s\nwant %s", i, g, tc.OK)
		}
	}
}

func TestOracleContainerLogs(t *testing.T) {
	for i, tc := range readOracle(t).Logs {
		out, errOut := newestContainerLogs(tc.Output, tc.ErrorOutput)
		if out != tc.OK[0] || errOut != tc.OK[1] {
			t.Errorf("case %d:\n got %q %q\nwant %q %q", i, out, errOut, tc.OK[0], tc.OK[1])
		}
	}
}

func TestOracleDisplay(t *testing.T) {
	for _, tc := range readOracle(t).Display {
		if got := displayText(unhex(t, tc.Input)); got != tc.OK {
			t.Errorf("%s: got %q, want %q", tc.Input, got, tc.OK)
		}
	}
}

func TestOracleHerdr(t *testing.T) {
	c := readOracle(t)
	for i, tc := range c.Herdr {
		agents, truncated, err := parseHerdrSnapshot(unhex(t, tc.Input))
		if (err != nil) != (tc.Error != "") {
			t.Errorf("case %d: %v, Python %q", i, err, tc.Error)
			continue
		}
		if err == nil && !sameJSON(t, tc.OK, map[string]any{"agents": agents, "truncated": truncated}) {
			g, _ := json.Marshal(agents)
			t.Errorf("case %d:\n got %s %v\nwant %s", i, g, truncated, tc.OK)
		}
	}
	for _, tc := range c.HerdrFailure {
		if got := herdrFailure(tc.Status, unhex(t, tc.Stderr)); got != tc.OK {
			t.Errorf("%d %s: %q, want %q", tc.Status, tc.Stderr, got, tc.OK)
		}
	}
}
