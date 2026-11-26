package legacy

import (
	json "encoding/json/v2"
	"math/rand/v2"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// Differential test against CPython's datetime.fromisoformat (the C
// module the Python release runs). It uses the repository's virtual
// environment and is skipped where it does not exist.
const pythonISO = `
import json, sys
from datetime import datetime
out = []
for s in json.load(sys.stdin):
    try:
        out.append(datetime.fromisoformat(s).isoformat())
    except Exception:
        out.append(None)
json.dump(out, sys.stdout)
`

func isoCandidates(n int) []string {
	r := rand.New(rand.NewPCG(1, 2))
	alphabet := []string{"0", "1", "2", "3", "4", "5", "9", "-", ":", ".", ",", "T", " ", "W", "Z", "+", "x", "ü", "24", "00", "\x00", "6", "7", "8"}
	bases := []string{"2026-11-02", "20261102", "2026-W44", "2026W44", "2026-W44-1", "2024-W53-7", "2026-02-29", "2024-02-29", "9999-12-31"}
	times := []string{"", "T09", " 09:00", "T0900", "T09:00:00", "T09:00:00.5", "T09:00:00,1234567", "T24:00", "T23:59:59.999999", "T09:00:00Z"}
	zones := []string{"", "Z", "+00:00", "-05", "+0130", "+01:30:15.5", "-23:59", "+24:00", "+1", "+123"}
	var out []string
	for _, b := range bases {
		for _, tm := range times {
			for _, z := range zones {
				out = append(out, b+tm+z)
			}
		}
	}
	for range n {
		var sb strings.Builder
		sb.WriteString(bases[r.IntN(len(bases))])
		for range r.IntN(16) {
			sb.WriteString(alphabet[r.IntN(len(alphabet))])
		}
		out = append(out, sb.String())
	}
	return out
}

func TestPythonISOFormatDifferential(t *testing.T) {
	t.Parallel()
	python := "../../../.venv/bin/python"
	if _, err := os.Stat(python); err != nil {
		t.Skip("no Python virtual environment")
	}
	inputs := isoCandidates(200000)
	payload, err := json.Marshal(inputs)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), python, "-I", "-c", pythonISO)
	cmd.Stdin = strings.NewReader(string(payload))
	raw, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	var want []*string
	if err := json.Unmarshal(raw, &want); err != nil || len(want) != len(inputs) {
		t.Fatalf("python output: %v", err)
	}
	mismatches := 0
	for i, in := range inputs {
		got, err := pythonFromISOFormatToISO(in)
		switch {
		case want[i] == nil && err == nil:
			t.Errorf("%q: Go accepts (%q), Python rejects", in, got)
		case want[i] != nil && (err != nil || got != *want[i]):
			t.Errorf("%q: Go %q, %v; Python %q", in, got, err, *want[i])
		default:
			continue
		}
		if mismatches++; mismatches > 20 {
			t.Fatal("too many mismatches")
		}
	}
}
