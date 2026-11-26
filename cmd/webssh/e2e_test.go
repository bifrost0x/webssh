//go:build e2e

package main

import (
	"bytes"
	"testing"
)

func TestE2ECommand(t *testing.T) {
	tests := []struct {
		name, port, seed string
		args             []string
		wantCode         int
		wantStderr       string
	}{
		{name: "arguments", args: []string{"x"}, wantCode: 2, wantStderr: "takes no arguments"},
		{name: "bad port", port: "http", wantCode: 2, wantStderr: "not a port number"},
		{name: "missing seed", seed: "missing.json", wantCode: 1, wantStderr: "missing.json"},
		// Until the composition root wires a server, the start fails
		// instead of serving a partial backend.
		{name: "not wired", wantCode: 1, wantStderr: "no HTTP server"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			seed := tt.seed
			if seed == "" {
				seed = "../../tests/e2e/seed.json"
			}
			t.Setenv(envE2ESeed, seed)
			t.Setenv(envE2EPort, tt.port)
			t.Setenv("TMPDIR", t.TempDir())
			var stdout, stderr bytes.Buffer
			code := run(append([]string{"e2e"}, tt.args...), &stdout, &stderr)
			if code != tt.wantCode {
				t.Errorf("code = %d, want %d; stderr %s", code, tt.wantCode, stderr.String())
			}
			assertOutput(t, "stdout", stdout.String(), "")
			assertOutput(t, "stderr", stderr.String(), tt.wantStderr)
		})
	}
}
