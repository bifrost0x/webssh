// Package admincli implements the administrator subcommands of webssh:
// create-admin, reset-password and ldap-secret.
//
// Operators know these commands from the Python release, where Click
// parsed them (app/cli.py, deployment/ldap_secret_cli.py), and documented
// procedures depend on their exact options, exit codes and messages (ADR
// 0011). The package therefore reproduces Click's behaviour for the option
// forms those commands accept: "--name value" and "--name=value", the last
// of repeated options wins, "--" ends the options, usage errors exit with
// 2, failures print "Error: …" and exit with 1, an aborted prompt prints
// "Aborted!" and exits with 1.
package admincli

import (
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
)

// Exit codes as Click returns them.
const (
	ExitOK    = 0
	ExitError = 1 // ClickException, Abort
	ExitUsage = 2 // UsageError
)

// IO holds the standard streams of one command run. Terminal opens the
// controlling terminal for hidden input; nil means there is none.
type IO struct {
	Stdin          io.Reader
	Stdout, Stderr io.Writer
	Terminal       func() (Terminal, error)
}

// failure is a ClickException: "Error: <message>" on stderr, exit 1.
type failure struct{ msg string }

func (f *failure) Error() string { return f.msg }

func fail(format string, args ...any) error { return &failure{msg: fmt.Sprintf(format, args...)} }

// errAbort is click.Abort: "Aborted!" on stderr, exit 1.
var errAbort = errors.New("aborted")

// usageError is a click.UsageError. withUsage adds the usage line and the
// hint to --help, as Click does for every usage error that knows its
// command; option values with a wrong arity are reported without them.
type usageError struct {
	msg       string
	withUsage bool
}

func (u *usageError) Error() string { return u.msg }

// option is one option of a command. A flag takes no value.
type option struct {
	name     string // "--username"
	metavar  string
	required bool
	flag     bool
}

// command describes the parsing of one command.
type command struct {
	// prog is the program name in usage lines ("flask", "webssh",
	// "ldap_secret_cli.py"), path the command path after it
	// ("create-admin", "ldap-secret set-password").
	prog, path string
	// usageArgs follows "[OPTIONS]" in the usage line ("[PEM_FILE]",
	// "COMMAND [ARGS]...").
	usageArgs string
	options   []option
	// maxArgs is the number of positional arguments the command takes.
	maxArgs int
	// help is the full --help text, as the Python release prints it.
	help string
}

// name is the program and the command path, as Click names a command.
func (c *command) name() string {
	return strings.TrimSpace(c.prog + " " + c.path)
}

func (c *command) usageLine() string {
	line := "Usage: " + c.name() + " [OPTIONS]"
	if c.usageArgs != "" {
		line += " " + c.usageArgs
	}
	return line
}

// parsed is the result of parsing a command's arguments.
type parsed struct {
	values map[string]string
	flags  map[string]bool
	args   []string
	help   bool
}

// value returns the value of an option and whether it was given.
func (p parsed) value(name string) (string, bool) {
	v, ok := p.values[name]
	return v, ok
}

// parse reads args like Click's OptionParser followed by the parameter
// processing of a command: unknown options and missing values fail during
// parsing, --help wins over every later check, then required options are
// checked in declaration order and surplus arguments last.
func (c *command) parse(args []string) (parsed, error) {
	p := parsed{values: map[string]string{}, flags: map[string]bool{}}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--":
			p.args = append(p.args, args[i+1:]...)
			i = len(args)
		case len(arg) > 1 && arg[0] == '-':
			consumed, err := c.parseOption(&p, arg, args[i+1:])
			if err != nil {
				return p, err
			}
			i += consumed
		default:
			p.args = append(p.args, arg)
		}
	}
	if p.help {
		return p, nil
	}
	for _, o := range c.options {
		if _, ok := p.values[o.name]; o.required && !ok {
			return p, &usageError{msg: fmt.Sprintf("Missing option '%s'.", o.name), withUsage: true}
		}
	}
	if len(p.args) > c.maxArgs {
		extra := p.args[c.maxArgs:]
		word := "argument"
		if len(extra) > 1 {
			word = "arguments"
		}
		return p, &usageError{msg: fmt.Sprintf("Got unexpected extra %s (%s)", word, strings.Join(extra, " ")), withUsage: true}
	}
	return p, nil
}

// parseOption handles one argument that starts with "-" and returns how
// many of the following arguments it consumed.
func (c *command) parseOption(p *parsed, arg string, rest []string) (int, error) {
	name, value, explicit := arg, "", false
	if strings.HasPrefix(arg, "--") {
		name, value, explicit = strings.Cut(arg, "=")
	} else {
		// Click tries the short form character by character; none of
		// these commands has short options, so the first one fails.
		name = arg[:2]
	}
	if name == "--help" {
		if explicit {
			return 0, &usageError{msg: "Option '--help' does not take a value."}
		}
		p.help = true
		return 0, nil
	}
	i := slices.IndexFunc(c.options, func(o option) bool { return o.name == name })
	if i < 0 {
		return 0, &usageError{msg: noSuchOption(name, c.longOptions()), withUsage: true}
	}
	o := c.options[i]
	switch {
	case o.flag && explicit:
		return 0, &usageError{msg: fmt.Sprintf("Option '%s' does not take a value.", name)}
	case o.flag:
		p.flags[name] = true
		return 0, nil
	case explicit:
		p.values[name] = value
		return 0, nil
	case len(rest) == 0:
		return 0, &usageError{msg: fmt.Sprintf("Option '%s' requires an argument.", name)}
	default:
		p.values[name] = rest[0]
		return 1, nil
	}
}

func (c *command) longOptions() []string {
	names := []string{"--help"}
	for _, o := range c.options {
		names = append(names, o.name)
	}
	return names
}

// noSuchOption is the message of click.NoSuchOption with its suggestions.
func noSuchOption(name string, known []string) string {
	msg := fmt.Sprintf("No such option '%s'.", name)
	switch close := closeMatches(name, known); len(close) {
	case 0:
	case 1:
		msg += fmt.Sprintf(" Did you mean '%s'?", close[0])
	default:
		slices.Sort(close)
		msg += " (Possible options: " + strings.Join(close, ", ") + ")"
	}
	return msg
}

// report writes the outcome of a command like Click's main and returns
// the exit code.
func (c *command) report(o IO, err error) int {
	var f *failure
	var u *usageError
	switch {
	case err == nil:
		return ExitOK
	case errors.As(err, &f):
		writeLine(o.Stderr, "Error: "+f.msg)
		return ExitError
	case errors.Is(err, errAbort):
		writeLine(o.Stderr, "Aborted!")
		return ExitError
	case errors.As(err, &u):
		if u.withUsage {
			fmt.Fprintf(o.Stderr, "%s\nTry '%s --help' for help.\n\n", c.usageLine(), c.name())
		}
		writeLine(o.Stderr, "Error: "+u.msg)
		return ExitUsage
	default:
		// An unexpected error: Click would print a traceback. The message
		// names the operation, never a secret value.
		writeLine(o.Stderr, "Error: "+err.Error())
		return ExitError
	}
}

func writeLine(w io.Writer, s string) {
	_, _ = io.WriteString(w, s+"\n")
}
