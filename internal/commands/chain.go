package commands

import (
	"strings"
	"unicode"
)

// The rules in this file turn the steps of a set into one startup text
// the way app/command_set_manager.py does: the sudo prefix per line, a
// no-op for comment-only steps and the " && " between steps that neither
// a trailing comment nor a trailing ";" or "&" can swallow. Positions are
// counted in code points, as Python counts them.

// sudoBoundaries are the characters that may follow "sudo" when a line
// already starts with it (SUDO_TOKEN_BOUNDARIES).
const sudoBoundaries = " \t;&|()<>"

// pySpace is str.isspace for one code point.
func pySpace(r rune) bool {
	switch r {
	case 0x1c, 0x1d, 0x1e, 0x1f:
		return true
	}
	return unicode.IsSpace(r)
}

func pyStrip(s string) string  { return strings.TrimFunc(s, pySpace) }
func pyLStrip(s string) string { return strings.TrimLeftFunc(s, pySpace) }
func pyRStrip(s string) string { return strings.TrimRightFunc(s, pySpace) }

// prefixSudo is _prefix_commands_with_sudo: every line that is not
// blank, a comment or already a sudo command gets "sudo " after its
// indentation.
func prefixSudo(value string) string {
	lines := strings.Split(value, "\n")
	for i, line := range lines {
		stripped := pyLStrip(line)
		leading := line[:len(line)-len(stripped)]
		already := stripped == "sudo" ||
			(strings.HasPrefix(stripped, "sudo") && len(stripped) > 4 && strings.ContainsRune(sudoBoundaries, rune(stripped[4])))
		if stripped == "" || strings.HasPrefix(stripped, "#") || already {
			continue
		}
		lines[i] = leading + "sudo " + stripped
	}
	return strings.Join(lines, "\n")
}

type position struct{ line, column int }

// shellTokens is _shell_token_positions: the column of the comment of
// each line and the positions of unquoted ";" and "&".
func shellTokens(value string) (comments map[int]int, semicolons, ampersands map[position]bool) {
	comments = map[int]int{}
	semicolons = map[position]bool{}
	ampersands = map[position]bool{}
	var single, double, escaped, comment bool
	wordStart := true
	line, column := 0, 0
	for _, c := range value {
		switch {
		case comment:
			if c == '\n' {
				comment = false
				wordStart = true
			}
		case escaped:
			escaped = false
			if c != '\n' {
				wordStart = false
			}
		case single:
			if c == '\'' {
				single = false
			}
		case double:
			if c == '"' {
				double = false
			} else if c == '\\' {
				escaped = true
			}
		case c == '\\':
			escaped = true
		case c == '\'':
			single = true
			wordStart = false
		case c == '"':
			double = true
			wordStart = false
		case c == '\n' || pySpace(c):
			wordStart = true
		case c == ';':
			semicolons[position{line, column}] = true
			wordStart = true
		case c == '&':
			ampersands[position{line, column}] = true
			wordStart = true
		case strings.ContainsRune("|()<>", c):
			wordStart = true
		case c == '#' && wordStart:
			comment = true
			comments[line] = column
		default:
			wordStart = false
		}
		if c == '\n' {
			line++
			column = 0
		} else {
			column++
		}
	}
	return comments, semicolons, ampersands
}

// appendOperator is _append_operator.
func appendOperator(text []rune, line int, semicolons, ampersands map[position]bool) string {
	end := position{line, len(text) - 1}
	switch {
	case semicolons[end]:
		return pyRStrip(string(text[:len(text)-1])) + " &&"
	case ampersands[end]:
		return string(text) + " : &&"
	}
	return string(text) + " &&"
}

// prepareStep is _prepare_step_for_chaining: trailing blank lines go, an
// empty step is ":" and a comment-only step gets ":" before it.
func prepareStep(value string) string {
	lines := strings.Split(value, "\n")
	for len(lines) > 0 && pyStrip(lines[len(lines)-1]) == "" {
		lines = lines[:len(lines)-1]
	}
	if len(lines) == 0 {
		return ":"
	}
	trimmed := strings.Join(lines, "\n")
	for _, l := range lines {
		if pyStrip(l) != "" && !strings.HasPrefix(pyLStrip(l), "#") {
			return trimmed
		}
	}
	return ":\n" + trimmed
}

// appendSeparator is _append_step_separator: the " && " goes after the
// last command text, before a trailing comment.
func appendSeparator(value string) string {
	lines := strings.Split(value, "\n")
	comments, semicolons, ampersands := shellTokens(value)
	last := len(lines) - 1
	if _, ok := comments[last]; !ok {
		lines[last] = appendOperator([]rune(lines[last]), last, semicolons, ampersands)
		return strings.Join(lines, "\n") + " "
	}
	commandLine := -1
	var commandText []rune
	var commentText string
	hasComment := false
	for n := last; n >= 0; n-- {
		runes := []rune(lines[n])
		before := runes
		at, ok := comments[n]
		if ok {
			before = runes[:at]
		}
		if pyStrip(string(before)) != "" {
			commandLine = n
			commandText = []rune(pyRStrip(string(before)))
			if ok {
				commentText, hasComment = string(runes[at:]), true
			}
			break
		}
	}
	if commandLine < 0 {
		lines = append([]string{": &&"}, lines...)
	} else {
		lines[commandLine] = appendOperator(commandText, commandLine, semicolons, ampersands)
		if hasComment {
			lines[commandLine] += " " + commentText
		}
	}
	return strings.Join(lines, "\n") + "\n"
}

// chainSteps is the join of _resolve_loaded_command_set: the resolved
// steps, with sudo when asked, as one text.
func chainSteps(parts []string, sudo bool) string {
	prepared := make([]string, len(parts))
	for i, p := range parts {
		if sudo {
			p = prefixSudo(p)
		}
		prepared[i] = prepareStep(p)
	}
	var b strings.Builder
	for _, p := range prepared[:len(prepared)-1] {
		b.WriteString(appendSeparator(p))
	}
	b.WriteString(prepared[len(prepared)-1])
	return b.String()
}
