package remotecmd

import (
	json "encoding/json/v2"
	"os"
	"testing"
)

// The exec line of a sudo step equals command_for of the Python release
// (app/automation_transport.py, shlex.quote) for the checked-in vectors
// of testdata/shlex_oracle.py.
func TestShellMatchesPythonShlex(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("testdata/shlex_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		C string `json:"c"`
		L string `json:"l"`
	}
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases) < 1000 {
		t.Fatalf("%d vectors", len(cases))
	}
	for _, c := range cases {
		cmd, err := Shell(c.C, true)
		if err != nil || cmd.Line != c.L {
			t.Errorf("%q: %q, %v; want %q", c.C, cmd.Line, err, c.L)
		}
	}
}
