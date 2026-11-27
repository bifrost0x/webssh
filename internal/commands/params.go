package commands

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

// The rules of app/command_parameters.py: a parameterised set has only
// argv steps whose program is a fixed name, and every placeholder is one
// whole argument. Values are quoted as single arguments and never stored.

var (
	paramName   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,31}$`)
	program     = regexp.MustCompile(`^[A-Za-z0-9_./+\-]{1,256}$`)
	placeholder = regexp.MustCompile(`^\{\{([A-Za-z_][A-Za-z0-9_]{0,31})\}\}$`)
	// interpreters are the programs that would run their arguments as
	// code; a parameterised set may not start them.
	interpreters = regexp.MustCompile(`(?i)^(?:sh|bash|dash|zsh|ksh|fish|csh|tcsh|eval|exec|source|\.|env|sudo|` +
		`busybox|command|nohup|xargs|python[0-9.]*|perl|ruby|node|php|powershell|pwsh)$`)
	// shellSafe is the set of characters shlex.quote leaves unquoted.
	shellUnsafe = regexp.MustCompile(`[^A-Za-z0-9_@%+=:,./-]`)
)

// Python's "\Z" matches at the very end only, as Go's "$" does without
// (?m): a trailing newline never matches.

// safeText is _safe_text: at most maximum code points, no C0 or C1
// control characters.
func safeText(v string, maximum int) bool {
	if !utf8.ValidString(v) || utf8.RuneCountInString(v) > maximum {
		return false
	}
	for _, r := range v {
		if r < 32 || (r >= 127 && r <= 159) {
			return false
		}
	}
	return true
}

// Messages of the parameter rules, as the page shows them.
const (
	msgDeclare        = "Declare between 1 and 20 command parameters"
	msgParamNames     = "Parameter names must be unique identifiers of at most 32 characters"
	msgParamOnlyName  = "Command parameter declarations only support a name"
	msgArgvSteps      = "Parameterized command sets require between 1 and 50 argument steps"
	msgArgvOnly       = "Parameterized command sets only support argument steps"
	msgArgText        = "Command arguments must be text without control characters, at most 1024 characters each"
	msgFixedProgram   = "Use a fixed program name; shell interpreters and execution wrappers are unsupported"
	msgUndeclared     = "Command argument references an undeclared parameter"
	msgWholeArgument  = "A parameter placeholder must occupy one whole argument"
	msgUnused         = "Every declared command parameter must be used in an argument"
	msgTemplateLength = "Command argument templates must not exceed 4096 characters"
	msgExactValues    = "Provide exactly the declared command parameter values"
	msgValueText      = "Parameter values must be text without control characters, at most 1024 characters each"
	msgInteractive    = "Parameterized command sets require interactive launch after connecting"
)

// rawParam is one declaration as stored: the members of the object, or
// nil when it is not an object.
type rawParam struct {
	members map[string]any
	isObj   bool
}

// rawArgvStep is one step of a parameterised set as stored.
type rawArgvStep struct {
	isObj   bool
	typ     any
	argv    []any
	argvSet bool // argv is a list
}

// validateParameterSet is validate_parameter_set over decoded values: ""
// when the declarations and argv templates are valid.
func validateParameterSet(params []rawParam, paramsList bool, steps []rawArgvStep, stepsList bool) string {
	if !paramsList || len(params) < 1 || len(params) > MaxParameters {
		return msgDeclare
	}
	names := map[string]bool{}
	for _, p := range params {
		var name string
		ok := false
		if p.isObj {
			name, ok = p.members["name"].(string)
		}
		if !ok || !paramName.MatchString(name) || names[name] {
			return msgParamNames
		}
		if len(p.members) != 1 {
			return msgParamOnlyName
		}
		names[name] = true
	}
	if !stepsList || len(steps) < 1 || len(steps) > MaxArgvSteps {
		return msgArgvSteps
	}
	used := map[string]bool{}
	total := 0
	for _, s := range steps {
		if !s.isObj || s.typ != string(StepArgv) || !s.argvSet || len(s.argv) < 1 || len(s.argv) > MaxArgvArgs {
			return msgArgvOnly
		}
		args := make([]string, len(s.argv))
		for i, a := range s.argv {
			text, ok := a.(string)
			if !ok || !safeText(text, MaxArgRunes) {
				return msgArgText
			}
			args[i] = text
		}
		base := args[0][strings.LastIndexByte(args[0], '/')+1:]
		if !program.MatchString(args[0]) || interpreters.MatchString(base) {
			return msgFixedProgram
		}
		for _, a := range args[1:] {
			if m := placeholder.FindStringSubmatch(a); m != nil {
				if !names[m[1]] {
					return msgUndeclared
				}
				used[m[1]] = true
			} else if strings.Contains(a, "{{") || strings.Contains(a, "}}") {
				return msgWholeArgument
			}
		}
		for _, a := range args {
			total += utf8.RuneCountInString(a)
		}
	}
	if len(used) != len(names) {
		return msgUnused
	}
	if total > MaxTemplateRunes {
		return msgTemplateLength
	}
	return ""
}

// shellQuote is shlex.quote.
func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	if !shellUnsafe.MatchString(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}

// resolveArgv is resolve_parameters after the set passed
// validateParameterSet: the steps with the values put in, each program
// single-quoted so that it can never be a shell keyword, joined with
// " && ".
func resolveArgv(steps [][]string, declared []string, values map[string]any, valuesObj, sudo bool) (string, string) {
	if !valuesObj || len(values) != len(declared) {
		return "", msgExactValues
	}
	for _, n := range declared {
		if _, ok := values[n]; !ok {
			return "", msgExactValues
		}
	}
	text := map[string]string{}
	for n, v := range values {
		s, ok := v.(string)
		if !ok || !safeText(s, MaxArgRunes) {
			return "", msgValueText
		}
		text[n] = s
	}
	commands := make([]string, len(steps))
	for i, argv := range steps {
		args := make([]string, len(argv))
		for j, a := range argv {
			if m := placeholder.FindStringSubmatch(a); m != nil {
				a = text[m[1]]
			}
			args[j] = a
		}
		line := "'" + strings.ReplaceAll(args[0], "'", `'"'"'`) + "'"
		for _, a := range args[1:] {
			line += " " + shellQuote(a)
		}
		if sudo {
			line = "sudo " + line
		}
		commands[i] = line
	}
	resolved, msg := normalizeStartup(strings.Join(commands, " && "))
	return resolved, msg
}

// normalizeStartup is normalize_startup_commands: at most 4096 code
// points, no NUL, line breaks as LF. The second result is the message of
// a refusal.
func normalizeStartup(v string) (string, string) {
	switch {
	case utf8.RuneCountInString(v) > MaxResolvedRunes:
		return "", "Startup commands must not exceed 4096 characters"
	case strings.IndexByte(v, 0) >= 0:
		return "", "Startup commands must not contain NUL bytes"
	case !utf8.ValidString(v):
		return "", "Startup commands must be valid UTF-8"
	}
	return strings.ReplaceAll(strings.ReplaceAll(v, "\r\n", "\n"), "\r", "\n"), ""
}

// validateCommandParameters is validate_command_parameters.
func validateCommandParameters(v string) string {
	switch {
	case utf8.RuneCountInString(v) > MaxResolvedRunes:
		return "Command parameters must not exceed 4096 characters"
	case !utf8.ValidString(v):
		return "Command parameters must be valid UTF-8"
	case len(v) > 4*MaxResolvedRunes:
		return "Command parameters exceed the UTF-8 byte limit"
	case strings.IndexByte(v, 0) >= 0:
		return "Commands cannot contain NUL bytes"
	}
	return ""
}
