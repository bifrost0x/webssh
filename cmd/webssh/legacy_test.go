package main

import (
	"slices"
	"strings"
	"testing"
)

func TestLegacyEntrypoint(t *testing.T) {
	t.Parallel()
	const ep = "/app/entrypoint.sh"
	tests := []struct {
		name       string
		argv       []string
		wantCode   int
		wantStderr string
	}{
		{name: "known command not built yet", argv: []string{ep, "flask", "--app", "start:app", "create-admin", "--username", "a"}, wantCode: 1, wantStderr: `"create-admin" is not available`},
		{name: "short app form", argv: []string{ep, "flask", "--app", "start", "reset-password"}, wantCode: 1, wantStderr: "not available"},
		{name: "equals form", argv: []string{ep, "flask", "--app=start:app", "rotate-secret-key"}, wantCode: 1, wantStderr: "not available"},
		{name: "unknown flask command", argv: []string{ep, "flask", "--app", "start:app", "shell"}, wantCode: 2, wantStderr: "Error: No such command 'shell'."},
		{name: "webssh subcommand is not a flask command", argv: []string{ep, "flask", "--app", "start:app", "serve"}, wantCode: 2, wantStderr: "No such command 'serve'"},
		{name: "other app", argv: []string{ep, "flask", "--app", "evil:app", "create-admin"}, wantCode: 2, wantStderr: `unknown flask application "evil:app"`},
		{name: "missing app", argv: []string{ep, "flask", "create-admin"}, wantCode: 2, wantStderr: "needs --app"},
		{name: "missing command", argv: []string{ep, "flask", "--app", "start:app"}, wantCode: 2, wantStderr: "needs a command"},
		{name: "option instead of command", argv: []string{ep, "flask", "--app", "start:app", "--debug", "create-admin"}, wantCode: 2, wantStderr: "needs a command"},
		{name: "shell command", argv: []string{ep, "sh", "-c", "id"}, wantCode: 2, wantStderr: "no shell"},
		{name: "old gunicorn command", argv: []string{ep, "gunicorn", "start:app"}, wantCode: 2, wantStderr: "only accepts"},
		{name: "webssh form under the old path", argv: []string{ep, "serve"}, wantCode: 2, wantStderr: "only accepts"},
		{name: "no arguments", argv: []string{ep}, wantCode: 2, wantStderr: "only accepts"},
		{name: "relative path", argv: []string{"./entrypoint.sh", "python"}, wantCode: 2, wantStderr: "only accepts"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			code, stdout, stderr := runArgs(t, tt.argv...)
			if code != tt.wantCode {
				t.Errorf("dispatch(%q) = %d, want %d (stderr %q)", tt.argv, code, tt.wantCode, stderr)
			}
			assertOutput(t, "stdout", stdout, "")
			assertOutput(t, "stderr", stderr, tt.wantStderr)
		})
	}
}

// A legacy command that exists as a subcommand runs with the remaining
// arguments, after the deprecation notice.
func TestLegacyEntrypointRunsSubcommand(t *testing.T) {
	t.Parallel()
	name, rest, err := parseLegacyArgs([]string{"flask", "--app", "start:app", "create-admin", "--username", "admin", "--password-file", "/run/pw"})
	if err != nil {
		t.Fatal(err)
	}
	if name != "create-admin" || !slices.Equal(rest, []string{"--username", "admin", "--password-file", "/run/pw"}) {
		t.Errorf("parseLegacyArgs = %q %q", name, rest)
	}
}

func TestIsLegacyEntrypoint(t *testing.T) {
	t.Parallel()
	for argv0, want := range map[string]bool{
		"/app/entrypoint.sh":     true,
		"entrypoint.sh":          true,
		"/app/webssh":            false,
		"webssh":                 false,
		"/app/entrypoint.sh.bak": false,
		"":                       false,
	} {
		if got := isLegacyEntrypoint(argv0); got != want {
			t.Errorf("isLegacyEntrypoint(%q) = %v, want %v", argv0, got, want)
		}
	}
}

func FuzzParseLegacyArgs(f *testing.F) {
	f.Add("flask\x00--app\x00start:app\x00create-admin\x00--username\x00a")
	f.Add("flask\x00--app=start\x00backup")
	f.Add("sh\x00-c\x00id")
	f.Add("")
	f.Fuzz(func(t *testing.T, joined string) {
		args := strings.Split(joined, "\x00")
		name, rest, err := parseLegacyArgs(args)
		if err != nil {
			return
		}
		if args[0] != "flask" || name == "" || strings.HasPrefix(name, "-") {
			t.Fatalf("accepted %q as command %q", args, name)
		}
		if len(rest) >= len(args) {
			t.Fatalf("rest %q not shorter than args %q", rest, args)
		}
		if !slices.Equal(rest, args[len(args)-len(rest):]) {
			t.Fatalf("rest %q is not the tail of %q", rest, args)
		}
	})
}
