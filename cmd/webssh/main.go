// Command webssh is the WebSSH server binary.
//
// It only wires packages together and provides the subcommands a container
// or service manager needs. The Go server is built alongside the Python
// application and replaces it in one release (see docs/adr).
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/bifrost0x/webssh/internal/buildinfo"
)

// streams are the standard streams of one command run.
type streams struct {
	stdin          io.Reader
	stdout, stderr io.Writer
}

// e2eCommand runs the backend of the end-to-end suite. It is set only in
// the build with the tag "e2e" (e2e.go); the release binary has no such
// command, and the usage text never lists it.
var e2eCommand func(args []string, stdout, stderr io.Writer) int

// command is one subcommand. run returns the process exit code: 0 on
// success, 1 when the command fails and 2 for invalid usage.
type command struct {
	name    string
	summary string
	run     func(ctx context.Context, args []string, s streams) int
}

// commands lists the subcommands in the order the usage text shows them.
func commands() []command {
	return []command{
		{name: "serve", summary: "run the server until SIGTERM or SIGINT", run: runServe},
		{name: "healthcheck", summary: "exit 0 when /ready on the local port answers", run: runHealthcheck},
		{name: "create-admin", summary: "create an administrator or promote an account", run: runCreateAdmin},
		{name: "reset-password", summary: "set a new password for a local account", run: runResetPassword},
		{name: "ldap-secret", summary: "manage the LDAP secret volume", run: runLDAPSecret},
		{name: "migrate", summary: "--dry-run or --replace the migration of the Python data", run: runMigrate},
		{name: "legacy", summary: "purge: remove the Python data after the migration", run: runLegacy},
		{name: "version", summary: "print the version and source revision", run: runVersion},
		{name: "help", summary: "show this help", run: runHelp},
	}
}

func lookup(name string) (command, bool) {
	cmds := commands()
	i := slices.IndexFunc(cmds, func(c command) bool { return c.name == name })
	if i < 0 {
		return command{}, false
	}
	return cmds[i], true
}

func usage() string {
	var b strings.Builder
	b.WriteString("Usage:\n  webssh <command> [options]\n\nCommands:\n")
	for _, c := range commands() {
		fmt.Fprintf(&b, "  %-15s %s\n", c.name, c.summary)
	}
	return b.String()
}

func main() {
	s := streams{stdin: os.Stdin, stdout: os.Stdout, stderr: os.Stderr}
	os.Exit(dispatch(context.Background(), os.Args, s))
}

// dispatch selects the argument form by the name the binary was started
// under: the image links /app/entrypoint.sh to the binary for the documented
// Python command form.
func dispatch(ctx context.Context, argv []string, s streams) int {
	if len(argv) > 0 && isLegacyEntrypoint(argv[0]) {
		return runLegacyEntrypoint(ctx, argv[1:], s)
	}
	if len(argv) > 0 && isPythonShim(argv[0]) {
		return runPythonShim(argv[1:], s)
	}
	var args []string
	if len(argv) > 1 {
		args = argv[1:]
	}
	return run(ctx, args, s)
}

// run executes one subcommand.
func run(ctx context.Context, args []string, s streams) int {
	if len(args) == 0 {
		return usageError(s.stderr, "")
	}
	name := args[0]
	if name == "-h" || name == "--help" {
		name = "help"
	}
	if name == "e2e" && e2eCommand != nil {
		return e2eCommand(args[1:], s.stdout, s.stderr)
	}
	c, ok := lookup(name)
	if !ok {
		return usageError(s.stderr, fmt.Sprintf("unknown command %q", args[0]))
	}
	return c.run(ctx, args[1:], s)
}

func runVersion(_ context.Context, args []string, s streams) int {
	if len(args) > 0 {
		return usageError(s.stderr, "version takes no arguments")
	}
	return write(s.stdout, buildinfo.Read().String()+"\n")
}

func runHelp(_ context.Context, _ []string, s streams) int {
	return write(s.stdout, usage())
}

func usageError(stderr io.Writer, message string) int {
	if message != "" {
		message = "webssh: " + message + "\n\n"
	}
	write(stderr, message+usage())
	return 2
}

func write(w io.Writer, text string) int {
	if _, err := io.WriteString(w, text); err != nil {
		return 1
	}
	return 0
}
