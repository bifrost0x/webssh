package main

import (
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
)

// legacyEntrypointName is the base name of the Python image's entrypoint.
// The Go image keeps /app/entrypoint.sh as a link to the binary (ADR 0011).
const legacyEntrypointName = "entrypoint.sh"

// legacyCommands are the top-level commands of the Python CLI (app/cli.py)
// that the deprecated form can name. Each maps to the webssh subcommand of
// the same name once that subcommand exists.
var legacyCommands = []string{
	"create-admin",
	"reset-password",
	"issue-factor-bootstrap",
	"rotate-secret-key",
	"connection-store",
	"backup",
}

// legacyApps are the values of flask --app that select the WebSSH
// application, as documented ("start:app") and in its short form ("start").
var legacyApps = []string{"start:app", "start"}

func isLegacyEntrypoint(argv0 string) bool {
	return filepath.Base(argv0) == legacyEntrypointName
}

// runLegacyEntrypoint accepts exactly the documented argument vector
//
//	/app/entrypoint.sh flask --app start:app <command> [options]
//
// and runs the webssh subcommand of the same name. The Python entrypoint
// ran any program it was given; the Go image has no shell or Python, so
// every other vector is refused instead of being guessed at.
func runLegacyEntrypoint(ctx context.Context, args []string, s streams) int {
	name, rest, err := parseLegacyArgs(args)
	if err != nil {
		write(s.stderr, "webssh: "+err.Error()+"\n"+legacyUsage)
		return 2
	}
	if !slices.Contains(legacyCommands, name) {
		write(s.stderr, fmt.Sprintf("Error: No such command '%s'.\n", name))
		return 2
	}
	c, ok := lookup(name)
	if !ok {
		write(s.stderr, fmt.Sprintf("webssh: the command %q is not available in this version.\n", name))
		return 1
	}
	write(s.stderr, fmt.Sprintf("webssh: the form \"/app/entrypoint.sh flask --app start:app %s\" is deprecated and will be removed in the next major release; use \"/app/webssh %s\".\n", name, name))
	return c.run(ctx, rest, s)
}

const legacyUsage = `Usage:
  /app/entrypoint.sh flask --app start:app <command> [options]   (deprecated)
  /app/webssh <command> [options]
`

// parseLegacyArgs splits "flask --app start:app <command> [args]" (also
// "--app=start:app" and the app "start") into the command and its
// arguments.
func parseLegacyArgs(args []string) (string, []string, error) {
	if len(args) == 0 || args[0] != "flask" {
		return "", nil, fmt.Errorf("%s only accepts the form \"flask --app start:app <command>\"; the image has no shell", legacyEntrypointName)
	}
	args = args[1:]
	var app string
	switch {
	case len(args) >= 2 && args[0] == "--app":
		app, args = args[1], args[2:]
	case len(args) >= 1 && strings.HasPrefix(args[0], "--app="):
		app, args = strings.TrimPrefix(args[0], "--app="), args[1:]
	default:
		return "", nil, fmt.Errorf("flask needs --app start:app before the command")
	}
	if !slices.Contains(legacyApps, app) {
		return "", nil, fmt.Errorf("unknown flask application %q", app)
	}
	if len(args) == 0 || args[0] == "" || args[0][0] == '-' {
		return "", nil, fmt.Errorf("flask --app %s needs a command", app)
	}
	return args[0], args[1:], nil
}
