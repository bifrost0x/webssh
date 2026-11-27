package hosts

import (
	"encoding/json/jsontext"
	"errors"
	"regexp"
	"strings"
	"unicode"
)

// The host exchange reads untrusted text with the rules of the Python
// release (app/profile_exchange.py): str.splitlines(), shlex.split with
// comments in POSIX mode, int() and the patterns below. They decide which
// configuration lines are refused, so they are reproduced exactly.

// pySplitLines is str.splitlines(): every line boundary Python knows,
// \r\n as one.
func pySplitLines(s string) []string {
	var lines []string
	start := 0
	for i, r := range s {
		if i < start {
			continue
		}
		switch r {
		case '\n', '\v', '\f', '\x1c', '\x1d', '\x1e', '\u0085', ' ', ' ':
			lines = append(lines, s[start:i])
			start = i + len(string(r))
		case '\r':
			lines = append(lines, s[start:i])
			start = i + 1
			if start < len(s) && s[start] == '\n' {
				start++
			}
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

var errShlex = errors.New("hosts: invalid quoting")

// shlexSplit is shlex.split(line, comments=True, posix=True) for one line
// without a line break: whitespace is space, tab, CR and LF; '#' starts a
// comment outside quotes, also inside a word; single quotes are literal;
// in double quotes a backslash escapes only '"' and '\'.
func shlexSplit(line string) ([]string, error) {
	const (
		stateSpace = iota
		stateWord
		stateSingle
		stateDouble
		stateEscape
	)
	var tokens []string
	var token strings.Builder
	state, escaped := stateSpace, stateWord
	quoted := false
	emit := func() {
		if token.Len() > 0 || quoted {
			tokens = append(tokens, token.String())
		}
		token.Reset()
		quoted = false
	}
	isSpace := func(r rune) bool { return r == ' ' || r == '\t' || r == '\r' || r == '\n' }
	runes := []rune(line)
	for i := 0; i <= len(runes); i++ {
		end := i == len(runes)
		var r rune
		if !end {
			r = runes[i]
		}
		switch state {
		case stateSpace, stateWord:
			switch {
			case end:
				emit()
				return tokens, nil
			case isSpace(r):
				if state == stateWord {
					emit()
				}
				state = stateSpace
			case r == '#':
				emit()
				return tokens, nil
			case r == '\\':
				escaped, state = stateWord, stateEscape
			case r == '\'':
				state = stateSingle
			case r == '"':
				state = stateDouble
			default:
				token.WriteRune(r)
				state = stateWord
			}
		case stateSingle, stateDouble:
			quoted = true
			switch {
			case end:
				return nil, errShlex
			case (state == stateSingle && r == '\'') || (state == stateDouble && r == '"'):
				state = stateWord
			case state == stateDouble && r == '\\':
				escaped, state = stateDouble, stateEscape
			default:
				token.WriteRune(r)
			}
		case stateEscape:
			if end {
				return nil, errShlex
			}
			if escaped == stateDouble && r != '\\' && r != '"' {
				token.WriteRune('\\')
			}
			token.WriteRune(r)
			state = escaped
		}
	}
	return tokens, nil
}

// pyIntText is int(str) rendered as a JSON integer: surrounding white
// space, an optional sign, and decimal digits of any script with single
// underscores between them. The value keeps every digit, as a Python int.
func pyIntText(s string) (jsontext.Value, bool) {
	s = pyStrip(s)
	neg := false
	if s != "" && (s[0] == '+' || s[0] == '-') {
		neg, s = s[0] == '-', s[1:]
	}
	if s == "" || strings.HasPrefix(s, "_") || strings.HasSuffix(s, "_") || strings.Contains(s, "__") {
		return nil, false
	}
	digits := make([]byte, 0, len(s))
	for _, r := range s {
		if r == '_' {
			continue
		}
		d, ok := decimalValue(r)
		if !ok {
			return nil, false
		}
		if len(digits) > 0 || d != 0 {
			digits = append(digits, "0123456789"[d])
		}
	}
	if len(digits) == 0 {
		return jsontext.Value("0"), true
	}
	if neg {
		digits = append([]byte{'-'}, digits...)
	}
	return jsontext.Value(digits), true
}

// decimalValue is the value of a decimal digit (category Nd). Unicode
// assigns them in runs that start at zero, so the value is the distance
// to the start of the run, modulo ten.
func decimalValue(r rune) (int, bool) {
	if !unicode.Is(unicode.Nd, r) {
		return 0, false
	}
	start := r
	for start > 0 && unicode.Is(unicode.Nd, start-1) {
		start--
	}
	return int(r-start) % 10, true
}

// pyWS is the class of characters Python's \s and str.isspace() match.
const pyWS = `[\t\n\v\f\r \x{1c}-\x{1f}\x{85}\x{a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}]`
const pyNonWS = `[^\t\n\v\f\r \x{1c}-\x{1f}\x{85}\x{a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}]`

var (
	// knownHostLine is _KNOWN_HOST: a line that looks like known_hosts.
	knownHostLine = regexp.MustCompile(`^` + pyWS + `*(?:@(?:cert-authority|revoked)` + pyWS + `+)?` + pyNonWS + `+` + pyWS +
		`+(?:ssh-|ecdsa-|sk-)` + pyNonWS + `+` + pyWS + `+[A-Za-z0-9+/]+={0,2}(?:` + pyWS + `|$)`)
	// exchangeAlias is _ALIAS, exchangeUser the plain username rule.
	exchangeAlias = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,128}$`)
	exchangeUser  = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,32}$`)
)

// pyTextValue is _text: a str of at most maximum characters, all printable.
func pyTextValue(s string, maximum int) bool {
	return pyLen(s) <= maximum && strings.IndexFunc(s, func(r rune) bool { return !pyPrintable(r) }) < 0
}

// aliasKey is str.casefold() of an alias. Aliases match exchangeAlias,
// which is ASCII, so lower-casing is exact.
func aliasKey(alias string) string { return strings.ToLower(alias) }

// asciiLower is str.lower() for comparing with the ASCII keywords of the
// import: of the characters outside ASCII only the Kelvin sign lowers to
// an ASCII letter, and no keyword contains a k.
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}
