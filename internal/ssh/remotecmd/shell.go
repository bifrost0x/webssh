package remotecmd

import (
	"strings"
	"unicode/utf8"
)

// MaxShellCommand is the largest command Shell accepts (the step limit of
// automation runbooks, 8192 bytes in app/automation_store.py).
const MaxShellCommand = 8 << 10

// maxShellLine bounds the line Shell builds: a command of MaxShellCommand
// single quotes grows fivefold under shellQuote.
const maxShellLine = 5*MaxShellCommand + len(sudoShellPrefix) + 2

const sudoShellPrefix = "sudo -n -- sh -c "

// Shell builds the Command for a command a user wrote for the login shell
// of the target account: an automation step. It is the exec request
// itself, as in the Python release (command_for in
// app/automation_transport.py), so the account's shell interprets it with
// its own syntax; that is the contract of existing runbooks. With sudo the
// line is "sudo -n -- sh -c <command quoted like shlex.quote>": the
// command runs under sh as root and a step that needs a sudo password
// fails instead of waiting for input. stdin is empty. The command is 1 to
// MaxShellCommand bytes of valid UTF-8 without NUL; line breaks are
// allowed, the shell reads them as it would in a script.
//
// Only automation steps use Shell: everything else WebSSH runs keeps user
// text off the command line (Script, Program, Word).
func Shell(command string, sudo bool) (Command, error) {
	if command == "" || len(command) > MaxShellCommand || !utf8.ValidString(command) || strings.IndexByte(command, 0) >= 0 {
		return Command{}, errInvalid
	}
	line := command
	if sudo {
		line = sudoShellPrefix + shellQuote(command)
	}
	return Command{Line: line, shell: true}, nil
}

// shellQuote is shlex.quote of Python: a word of only safe characters
// stays as is, everything else is put in single quotes with each single
// quote written as '"'"'.
func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	if !strings.ContainsFunc(s, unsafeShellRune) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}

// unsafeShellRune matches the pattern [^\w@%+=:,./-] of shlex.quote with
// re.ASCII.
func unsafeShellRune(r rune) bool {
	switch {
	case 'a' <= r && r <= 'z', 'A' <= r && r <= 'Z', '0' <= r && r <= '9':
		return false
	case strings.ContainsRune("_@%+=:,./-", r):
		return false
	}
	return true
}
