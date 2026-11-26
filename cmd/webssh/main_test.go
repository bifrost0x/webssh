package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRun(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStdout string
		wantStderr string
	}{
		{name: "version", args: []string{"version"}, wantCode: 0, wantStdout: "dev"},
		{name: "help", args: []string{"help"}, wantCode: 0, wantStdout: "Usage:"},
		{name: "help flag", args: []string{"-h"}, wantCode: 0, wantStdout: "Usage:"},
		{name: "no command", args: nil, wantCode: 2, wantStderr: "Usage:"},
		{name: "unknown command", args: []string{"serve"}, wantCode: 2, wantStderr: `unknown command "serve"`},
		{name: "version with extra argument", args: []string{"version", "--json"}, wantCode: 2, wantStderr: "takes no arguments"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var stdout, stderr bytes.Buffer
			code := run(tt.args, &stdout, &stderr)
			if code != tt.wantCode {
				t.Errorf("run(%q) = %d, want %d", tt.args, code, tt.wantCode)
			}
			assertOutput(t, "stdout", stdout.String(), tt.wantStdout)
			assertOutput(t, "stderr", stderr.String(), tt.wantStderr)
		})
	}
}

func assertOutput(t *testing.T, stream, got, want string) {
	t.Helper()
	if want == "" {
		if got != "" {
			t.Errorf("%s = %q, want empty", stream, got)
		}
		return
	}
	if !strings.Contains(got, want) {
		t.Errorf("%s = %q, want it to contain %q", stream, got, want)
	}
}
