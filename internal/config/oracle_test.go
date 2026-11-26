package config

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// The differential tests compare this package with the Python release.
// The oracle is testdata/pyprobe.py, run by the repository's virtual
// environment (or WEBSSH_PYTHON). Its answers for a fixed set of inputs
// are checked in under testdata, so the comparison also runs where Python
// is missing; -update rewrites them from the oracle.
var update = flag.Bool("update", false, "rewrite the Python vectors in testdata from the oracle")

const repoRoot = "../.."

func pythonPath() string {
	if p := os.Getenv("WEBSSH_PYTHON"); p != "" {
		return p
	}
	return filepath.Join(repoRoot, ".venv", "bin", "python")
}

type oracle struct {
	in  *json.Encoder
	out *bufio.Scanner
}

// startOracle starts the Python oracle, or returns nil when Python is not
// available.
func startOracle(t testing.TB) *oracle {
	t.Helper()
	python := pythonPath()
	if _, err := os.Stat(python); err != nil {
		return nil
	}
	root, err := filepath.Abs(repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), python, "-I", "testdata/pyprobe.py", root)
	cmd.Env = []string{"LANG=C.UTF-8", "PATH=" + os.Getenv("PATH")}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = stdin.Close()
		_ = cmd.Wait()
	})
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	return &oracle{in: json.NewEncoder(stdin), out: sc}
}

func (o *oracle) ask(t testing.TB, req, resp any) {
	t.Helper()
	if err := o.in.Encode(req); err != nil {
		t.Fatalf("oracle request: %v", err)
	}
	if !o.out.Scan() {
		t.Fatalf("oracle ended: %v", o.out.Err())
	}
	if err := json.Unmarshal(o.out.Bytes(), resp); err != nil {
		t.Fatalf("oracle answer: %v", err)
	}
}

// requireOracle returns the oracle, failing under -update and skipping
// otherwise when Python is missing.
func requireOracle(t testing.TB) *oracle {
	t.Helper()
	o := startOracle(t)
	if o == nil {
		if *update {
			t.Fatal("-update needs the Python oracle")
		}
		t.Skip("no Python virtual environment")
	}
	return o
}

// writeJSONLines writes one JSON value per line, which keeps the files
// diffable.
func writeJSONLines[T any](t testing.TB, name string, items []T) {
	t.Helper()
	var buf bytes.Buffer
	for _, item := range items {
		line, err := json.Marshal(item)
		if err != nil {
			t.Fatal(err)
		}
		buf.Write(line)
		buf.WriteByte('\n')
	}
	if err := os.WriteFile(filepath.Join("testdata", name), buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

func readJSONLines[T any](t testing.TB, name string) []T {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	var out []T
	for line := range bytes.Lines(data) {
		var item T
		if err := json.Unmarshal(line, &item); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		out = append(out, item)
	}
	return out
}

func canonicalJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "<" + err.Error() + ">"
	}
	var x any
	if err := json.Unmarshal(b, &x); err != nil {
		return "<" + err.Error() + ">"
	}
	b, _ = json.Marshal(x)
	return string(b)
}
