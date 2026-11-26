package settings

import (
	"bytes"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"os"
	"testing"
)

// The oracle (testdata/oracle.py) records how the Python release judges
// and encodes the values below; the Go rules must agree on every case.
type oracleCase struct {
	In    string         `json:"in"`
	OK    bool           `json:"ok"`
	Known jsontext.Value `json:"known"`
	Out   string         `json:"out"`
}

func loadOracle(t *testing.T) map[string][]oracleCase {
	t.Helper()
	raw, err := os.ReadFile("testdata/oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases map[string][]oracleCase
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	return cases
}

// value parses an oracle input the way a request body is parsed. A value
// Go's parser refuses (Python reads 1e400 as inf) is nil.
func value(t *testing.T, text string) jsontext.Value {
	t.Helper()
	v := jsontext.Value(text)
	if !v.IsValid() {
		t.Fatalf("invalid JSON %q", text)
	}
	c, err := compact(v)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestOracleTerminalAppearance(t *testing.T) {
	for _, c := range loadOracle(t)["appearance"] {
		if got := ValidTerminalAppearance(value(t, c.In)); got != c.OK {
			t.Errorf("%s: Go %v, Python %v", c.In, got, c.OK)
		}
	}
}

func TestOracleOverviewPanels(t *testing.T) {
	for _, c := range loadOracle(t)["panels"] {
		v := value(t, c.In)
		if got := ValidOverviewPanels(v); got != c.OK {
			t.Errorf("%s: Go %v, Python %v", c.In, got, c.OK)
		}
		known := knownPanels(v)
		got := "null"
		if len(known) > 0 {
			got, _ = PythonJSON(joinArray(known))
		}
		var want string
		if err := json.Unmarshal(c.Known, &want); err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("%s: kept %s, Python %s", c.In, got, want)
		}
	}
}

func TestOracleOverviewDismissed(t *testing.T) {
	for _, c := range loadOracle(t)["dismissed"] {
		v := value(t, c.In)
		if got := ValidOverviewDismissed(v); got != c.OK {
			t.Errorf("%s: Go %v, Python %v", c.In, got, c.OK)
		}
		got, err := json.Marshal(knownDismissed(v))
		if err != nil {
			t.Fatal(err)
		}
		want, _ := compact(c.Known)
		if !bytes.Equal(got, want) {
			t.Errorf("%s: kept %s, Python %s", c.In, got, want)
		}
	}
}

func TestOracleSettingsFiles(t *testing.T) {
	for _, c := range loadOracle(t)["files"] {
		_, err := parseLegacyDocument(value(t, c.In))
		if got := err == nil; got != c.OK {
			t.Errorf("%s: Go %v (%v), Python %v", c.In, got, err, c.OK)
		}
	}
}

func TestOraclePythonJSON(t *testing.T) {
	for _, c := range loadOracle(t)["encode"] {
		got, err := PythonJSON(value(t, c.In))
		if err != nil {
			t.Fatalf("%s: %v", c.In, err)
		}
		if got != c.Out {
			t.Errorf("%s:\nGo     %s\nPython %s", c.In, got, c.Out)
		}
	}
}
