package remotecmd

import (
	"strings"
	"unicode/utf8"
)

// MaxScript is the largest script Script accepts (the step limit of
// automation runbooks).
const MaxScript = 8 << 10

// Script lines. The script itself travels on stdin, so no user text is
// ever part of the command line; the remote sh reads all of it and runs
// it with eval, which leaves the script with an exhausted stdin, as the
// Python release closed stdin after sending the command. With sudo the
// line is "sudo -n": a step that needs a sudo password fails with a
// non-zero exit status instead of waiting for input. No password is ever
// written to sudo.
const (
	scriptLine     = `sh -c 'eval "$(cat)"'`
	sudoScriptLine = `sudo -n -- sh -c 'eval "$(cat)"'`
)

// Script builds the Command for a user-written shell script (automation
// steps, command sets run as a step). The body is 1 to MaxScript bytes of
// valid UTF-8 without NUL; line breaks are allowed. Timeout and MaxOutput
// keep their meaning.
func Script(body string, sudo bool) (Command, error) {
	if body == "" || len(body) > MaxScript || !utf8.ValidString(body) || strings.IndexByte(body, 0) >= 0 {
		return Command{}, errInvalid
	}
	line := scriptLine
	if sudo {
		line = sudoScriptLine
	}
	return Command{Line: line, Stdin: []byte(body)}, nil
}

// Program builds the Command for a fixed shell program of WebSSH itself
// (the collectors of session insights and the runtime inventory). It
// travels on stdin like a Script, so it is read by sh whatever the
// account's login shell is; it may be up to MaxStdin bytes. The body must
// be text of the caller, never user input.
func Program(body string) (Command, error) {
	if body == "" || len(body) > MaxStdin || !utf8.ValidString(body) || strings.IndexByte(body, 0) >= 0 {
		return Command{}, errInvalid
	}
	return Command{Line: scriptLine, Stdin: []byte(body)}, nil
}
