package terminal

import (
	"context"
	json "encoding/json/v2"
	"os"
	"strings"
	"testing"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
)

// testdata/python_vectors.json is produced by testdata/python_vectors.py
// from the unchanged Python modules; see the script for the command.
type pyVectors struct {
	Python    string `json:"python"`
	Normalize []struct {
		In    string `json:"in"`
		Out   string `json:"out"`
		Error string `json:"error"`
		Input string `json:"input"`
	} `json:"normalize"`
	Parameters []struct {
		In    string `json:"in"`
		Error string `json:"error"`
	} `json:"parameters"`
	Commands []struct {
		ID         string `json:"id"`
		Command    string `json:"command"`
		Parameters string `json:"parameters"`
	} `json:"commands"`
	Sets map[string]struct {
		Text  string `json:"text"`
		Error string `json:"error"`
	} `json:"sets"`
	Resolution []struct {
		Payload map[string]*string `json:"payload"`
		Text    string             `json:"text"`
		Error   string             `json:"error"`
	} `json:"resolution"`
	TmuxNames []struct {
		Prefix string `json:"prefix"`
		User   string `json:"user"`
		Host   string `json:"host"`
		Port   int    `json:"port"`
		Suffix string `json:"suffix"`
		Name   string `json:"name"`
	} `json:"tmux_names"`
	TmuxCommands []struct {
		Program  string `json:"program"`
		Name     string `json:"name"`
		Reattach bool   `json:"reattach"`
		Line     string `json:"line"`
	} `json:"tmux_commands"`
	Herdr struct {
		Available string `json:"available"`
		Session   string `json:"session"`
	} `json:"herdr"`
}

func loadVectors(t *testing.T) pyVectors {
	t.Helper()
	raw, err := os.ReadFile("testdata/python_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v pyVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Normalize) < 200 || len(v.Resolution) < 600 || len(v.TmuxNames) < 150 {
		t.Fatalf("vector file is incomplete: %d texts, %d payloads, %d names", len(v.Normalize), len(v.Resolution), len(v.TmuxNames))
	}
	return v
}

func message(err error) string {
	if err == nil {
		return ""
	}
	if f, ok := fault.From(err); ok {
		return f.Message
	}
	return err.Error()
}

func TestStartupNormalizationMatchesPython(t *testing.T) {
	v := loadVectors(t)
	for _, c := range v.Normalize {
		out, err := normalizeStartup(c.In)
		if message(err) != c.Error || out != c.Out {
			t.Errorf("%q: python %q %q, go %q %q", c.In, c.Out, c.Error, out, message(err))
			continue
		}
		if err == nil && string(terminalInput(out)) != c.Input {
			t.Errorf("%q: python input %q, go %q", c.In, c.Input, terminalInput(out))
		}
	}
	for _, c := range v.Parameters {
		if got := message(validateParameters(c.In)); got != c.Error {
			t.Errorf("parameters %q: python %q, go %q", c.In, c.Error, got)
		}
	}
}

// vectorLibrary serves the fixed library of the vector script.
type vectorLibrary struct{ v *pyVectors }

func (l vectorLibrary) Command(_ context.Context, _ int64, id string) (string, string, error) {
	for _, c := range l.v.Commands {
		if c.ID == id {
			return c.Command, c.Parameters, nil
		}
	}
	return "", "", fault.New(fault.NotFound, "Command not found")
}

func (l vectorLibrary) ResolveSet(_ context.Context, _ int64, id string) (string, error) {
	s, ok := l.v.Sets[id]
	switch {
	case !ok:
		return "", fault.New(fault.NotFound, "Command set not found")
	case s.Error != "":
		return "", fault.New(fault.InvalidValue, s.Error)
	}
	return s.Text, nil
}

// The payloads of the vector file are ssh_connect members; the shim puts
// them into terminal.open's startup unchanged (a null is a missing member).
func startupOf(p map[string]*string) *protocol.Startup {
	get := func(k string) string {
		if v := p[k]; v != nil {
			return *v
		}
		return ""
	}
	return &protocol.Startup{Mode: get("startup_mode"), Commands: get("startup_commands"), CommandID: get("command_id"),
		CommandSetID: get("command_set_id"), ParametersOverride: p["parameters_override"]}
}

func TestStartupResolutionMatchesPython(t *testing.T) {
	v := loadVectors(t)
	m := &Manager{commands: vectorLibrary{&v}}
	for _, c := range v.Resolution {
		text, err := m.resolveStartup(t.Context(), 1, startupOf(c.Payload))
		if message(err) != c.Error || text != c.Text {
			t.Errorf("%v: python %q %q, go %q %q", c.Payload, c.Text, c.Error, text, message(err))
		}
	}
}

func TestStartupWithoutLibraryIsNotAvailable(t *testing.T) {
	m := &Manager{}
	for _, s := range []*protocol.Startup{{CommandID: "c"}, {Mode: startupSet, CommandSetID: "s"}} {
		if _, err := m.resolveStartup(t.Context(), 1, s); fault.CodeOf(err) != fault.NotAvailableInPreview {
			t.Errorf("%+v: %v", s, err)
		}
	}
	if text, err := m.resolveStartup(t.Context(), 1, &protocol.Startup{Commands: "ls\r\n"}); err != nil || text != "ls\n" {
		t.Errorf("free text without a library: %q %v", text, err)
	}
}

// The name scheme agrees with the Python release wherever that release
// produced a name a reattach accepts; Go also keeps longer names within
// the reattach limit (fix) by shortening the host part.
func TestTmuxNamesMatchPython(t *testing.T) {
	v := loadVectors(t)
	same := 0
	for _, c := range v.TmuxNames {
		got := tmuxNameWith(c.Prefix, c.User, c.Host, c.Port, c.Suffix)
		if !validTmuxName(got) {
			t.Fatalf("go name %q is not reattachable", got)
		}
		if validTmuxName(c.Name) {
			same++
			if got != c.Name {
				t.Errorf("%+v: python %q, go %q", c, c.Name, got)
			}
		}
	}
	if same < 100 {
		t.Fatalf("only %d comparable names", same)
	}
}

func TestTmuxCommandsMatchPython(t *testing.T) {
	v := loadVectors(t)
	for _, c := range v.TmuxCommands {
		// remotecmd.Word quotes every word, shlex.quote only unsafe ones;
		// the names hold no quote, so without the quotes both lines are
		// the same words.
		got, err := tmuxAttachCommand(c.Program, c.Name, c.Reattach)
		if err != nil || strings.ReplaceAll(got, "'", "") != c.Line {
			t.Errorf("%+v: go %q %v", c, got, err)
		}
	}
	if tmuxProgram(true) != "env LANG=C.UTF-8 LC_ALL=C.UTF-8 tmux -u" || tmuxProgram(false) != "tmux" {
		t.Error("tmux programs differ")
	}
	if v.Herdr.Available != herdrAvailableCommand || v.Herdr.Session != herdrSessionCommand {
		t.Errorf("herdr commands: python %+v", v.Herdr)
	}
}
