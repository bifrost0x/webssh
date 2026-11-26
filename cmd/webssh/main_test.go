package main

import (
	"bytes"
	"strings"
	"testing"
)

func runArgs(t *testing.T, argv ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = dispatch(t.Context(), argv, streams{stdin: strings.NewReader(""), stdout: &out, stderr: &errOut})
	return code, out.String(), errOut.String()
}

func TestRun(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		argv       []string
		wantCode   int
		wantStdout string
		wantStderr string
	}{
		{name: "version", argv: []string{"webssh", "version"}, wantCode: 0, wantStdout: "dev"},
		{name: "help", argv: []string{"webssh", "help"}, wantCode: 0, wantStdout: "Usage:"},
		{name: "help lists serve", argv: []string{"webssh", "help"}, wantCode: 0, wantStdout: "healthcheck"},
		{name: "help flag", argv: []string{"webssh", "-h"}, wantCode: 0, wantStdout: "Usage:"},
		{name: "long help flag", argv: []string{"/app/webssh", "--help"}, wantCode: 0, wantStdout: "Usage:"},
		{name: "no command", argv: []string{"webssh"}, wantCode: 2, wantStderr: "Usage:"},
		{name: "empty argv", argv: nil, wantCode: 2, wantStderr: "Usage:"},
		{name: "unknown command", argv: []string{"webssh", "flask"}, wantCode: 2, wantStderr: `unknown command "flask"`},
		{name: "version with extra argument", argv: []string{"webssh", "version", "--json"}, wantCode: 2, wantStderr: "takes no arguments"},
		{name: "serve with positional argument", argv: []string{"webssh", "serve", "extra"}, wantCode: 2, wantStderr: "no positional arguments"},
		{name: "serve with bad bind", argv: []string{"webssh", "serve", "--bind", "0.0.0.0"}, wantCode: 2, wantStderr: "--bind"},
		{name: "serve with unknown flag", argv: []string{"webssh", "serve", "--port", "1"}, wantCode: 2, wantStderr: "flag provided but not defined"},
		{name: "healthcheck with argument", argv: []string{"webssh", "healthcheck", "x"}, wantCode: 2, wantStderr: "healthcheck takes only"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			code, stdout, stderr := runArgs(t, tt.argv...)
			if code != tt.wantCode {
				t.Errorf("dispatch(%q) = %d, want %d", tt.argv, code, tt.wantCode)
			}
			assertOutput(t, "stdout", stdout, tt.wantStdout)
			assertOutput(t, "stderr", stderr, tt.wantStderr)
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
