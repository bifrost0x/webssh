package oracletest

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// helperEnv names the scenario TestHelper runs in a child process.
const helperEnv = "ORACLETEST_HELPER"

type answer struct {
	Values []string          `json:"values"`
	Byname map[string]string `json:"byname"`
	Empty  []string          `json:"empty"`
}

// fakeRelease is a repository root with app/__init__.py and an
// executable standing in for the interpreter; the ask functions of these
// tests never run it.
func fakeRelease(t *testing.T) (python, root string) {
	t.Helper()
	root = t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "app"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "app", "__init__.py"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	python = filepath.Join(root, "python")
	if err := os.WriteFile(python, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil { // #nosec G306 -- an executable stand-in
		t.Fatal(err)
	}
	return python, root
}

func record(t *testing.T, path, python, root string, a answer) {
	t.Helper()
	recordWith(t, path, python, root, "CPython 0.0", a)
}

func recordWith(t *testing.T, path, python, root, version string, a answer) {
	t.Helper()
	t.Run("record", func(t *testing.T) {
		t.Setenv(ModeEnv, "record")
		t.Setenv(PythonEnv, python)
		t.Setenv(RootEnv, root)
		t.Setenv(SourceEnv, "0000000 (test)")
		t.Setenv(VersionEnv, version)
		rec := Open(t, path)
		got := Ask(t, rec, "case", "request", func(Release) answer { return a })
		if (got.Empty == nil) != (a.Empty == nil) || got.Byname != nil {
			t.Errorf("record mode returned %+v, not the round trip", got)
		}
	})
}

func TestRecordThenReplay(t *testing.T) {
	python, root := fakeRelease(t)
	path := filepath.Join(t.TempDir(), "rec.json")
	record(t, path, python, root, answer{Values: []string{"a", "b"}, Empty: []string{}})
	t.Setenv(ModeEnv, "")
	rec := Open(t, path)
	if h := rec.Header(); h.Python != "CPython 0.0" || h.Source != "0000000 (test)" || h.Recorder != recorder {
		t.Fatalf("header %+v", h)
	}
	got := Ask(t, rec, "case", "request", func(Release) answer {
		t.Fatal("replay asked the Python release")
		return answer{}
	})
	if len(got.Values) != 2 || got.Byname != nil || got.Empty == nil {
		t.Fatalf("replayed %+v; nil and empty must survive", got)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "\"values\":[\"a\",\"b\"]") {
		t.Errorf("recording:\n%s", raw)
	}
}

// Recording unchanged answers again keeps the file, header included;
// changed answers get the new header.
func TestRecordKeepsTheHeaderOfUnchangedAnswers(t *testing.T) {
	python, root := fakeRelease(t)
	path := filepath.Join(t.TempDir(), "rec.json")
	record(t, path, python, root, answer{Values: []string{"a"}})
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	recordWith(t, path, python, root, "CPython 0.1", answer{Values: []string{"a"}})
	if after, _ := os.ReadFile(path); string(after) != string(before) {
		t.Fatalf("unchanged answers rewrote the recording:\n%s", after)
	}
	recordWith(t, path, python, root, "CPython 0.1", answer{Values: []string{"b"}})
	t.Setenv(ModeEnv, "")
	if h := Open(t, path).Header(); h.Python != "CPython 0.1" {
		t.Fatalf("changed answers kept the old header: %+v", h)
	}
}

func TestLiveComparesWithTheRecording(t *testing.T) {
	python, root := fakeRelease(t)
	path := filepath.Join(t.TempDir(), "rec.json")
	record(t, path, python, root, answer{Values: []string{"a"}})
	t.Setenv(ModeEnv, "live")
	t.Setenv(PythonEnv, python)
	t.Setenv(RootEnv, root)
	rec := Open(t, path)
	asked := false
	got := Ask(t, rec, "case", "request", func(r Release) answer {
		asked = r.Python == python && r.Root == root
		return answer{Values: []string{"a"}}
	})
	if !asked || len(got.Values) != 1 {
		t.Fatalf("live mode: asked %v, %+v", asked, got)
	}
}

// TestHelper runs one failure scenario in a child process.
func TestHelper(t *testing.T) {
	scenario := os.Getenv(helperEnv)
	if scenario == "" {
		t.Skip("helper process of TestFailures")
	}
	dir := os.Getenv("ORACLETEST_DIR")
	path := filepath.Join(dir, "rec.json")
	ask := func(Release) answer { return answer{Values: []string{"changed"}} }
	switch scenario {
	case "missing":
		Open(t, filepath.Join(dir, "none.json"))
	case "request":
		Ask(t, Open(t, path), "case", "another request", ask)
	case "key":
		Ask(t, Open(t, path), "another key", "request", ask)
	case "live-differs", "live-without-python", "live-without-root", "mode", "record-without-source":
		Ask(t, Open(t, path), "case", "request", ask)
	case "require-live":
		RequireLive(t)
	}
	t.Log("scenario passed")
}

func TestFailures(t *testing.T) {
	python, root := fakeRelease(t)
	dir := t.TempDir()
	record(t, filepath.Join(dir, "rec.json"), python, root, answer{Values: []string{"a"}})
	for _, tc := range []struct {
		scenario, mode, python, want string
		noRoot                       bool
	}{
		{"missing", "", "", "record it with", false},
		{"request", "", "", "changed since it was recorded", false},
		{"key", "", "", "has no answer", false},
		{"live-differs", "live", python, "answers \"case\" differently", false},
		{"live-without-python", "live", filepath.Join(dir, "no-python"), "needs the Python release", false},
		{"live-without-root", "live", python, "needs the Python release in " + RootEnv, true},
		{"mode", "replay", "", "want unset, live or record", false},
		{"record-without-source", "record", python, "recording needs", false},
		{"require-live", "live", filepath.Join(dir, "no-python"), "needs the Python release", false},
	} {
		t.Run(tc.scenario, func(t *testing.T) {
			cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestHelper$", "-test.count=1", "-test.v") // #nosec G204 -- the test binary itself
			rootValue := root
			if tc.noRoot {
				rootValue = ""
			}
			cmd.Env = append(os.Environ(), helperEnv+"="+tc.scenario, "ORACLETEST_DIR="+dir, ModeEnv+"="+tc.mode,
				PythonEnv+"="+tc.python, RootEnv+"="+rootValue, SourceEnv+"=", VersionEnv+"=")
			out, err := cmd.CombinedOutput()
			if err == nil || !strings.Contains(string(out), tc.want) || strings.Contains(string(out), "--- SKIP") {
				t.Fatalf("want a failure with %q, got %v:\n%s", tc.want, err, out)
			}
		})
	}
}

func TestRequireLiveSkipsInReplay(t *testing.T) {
	dir := t.TempDir()
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestHelper$", "-test.count=1", "-test.v") // #nosec G204 -- the test binary itself
	cmd.Env = append(os.Environ(), helperEnv+"=require-live", "ORACLETEST_DIR="+dir, ModeEnv+"=")
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "--- SKIP") || !strings.Contains(string(out), ModeEnv+"=live") {
		t.Fatalf("want a skip that names %s=live, got %v:\n%s", ModeEnv, err, out)
	}
}

// Without WEBSSH_PYTHON the interpreter is the one of the release's own
// virtual environment, not one of this repository.
func TestRequireDefaultsToTheReleaseInterpreter(t *testing.T) {
	_, root := fakeRelease(t)
	venv := filepath.Join(root, ".venv", "bin")
	if err := os.MkdirAll(venv, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(venv, "python"), []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil { // #nosec G306 -- an executable stand-in
		t.Fatal(err)
	}
	t.Setenv(PythonEnv, "")
	t.Setenv(RootEnv, root)
	if r := Require(t); r.Python != filepath.Join(venv, "python") || r.Root != root {
		t.Fatalf("release %+v", r)
	}
}
