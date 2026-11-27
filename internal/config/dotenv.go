package config

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// The .env parser of python-dotenv (version in requirements.txt), which
// config.py runs with load_dotenv(BASE_DIR / '.env'): override=False and
// interpolation on. The functions follow dotenv/parser.py and
// dotenv/variables.py rule by rule; the differential tests compare them
// with the library. Text is handled as code points, as in Python.

// EnvAssignment is one variable a .env file adds to the environment.
type EnvAssignment struct {
	Name, Value string
}

// dotenvBinding is one statement of the file (parser.Binding).
type dotenvBinding struct {
	key, value       string
	hasKey, hasValue bool
	// line is where the statement starts, counted like python-dotenv:
	// blank lines before it belong to it.
	line int
	err  bool
}

type dotenvReader struct {
	s    []rune
	pos  int
	line int
}

func (r *dotenvReader) hasNext() bool { return r.pos < len(r.s) }

// peek returns the next code point, or -1 at the end.
func (r *dotenvReader) peek() rune {
	if r.pos >= len(r.s) {
		return -1
	}
	return r.s[r.pos]
}

// advanceTo moves to position end and counts the line feeds passed.
func (r *dotenvReader) advanceTo(end int) {
	for _, c := range r.s[r.pos:end] {
		if c == '\n' {
			r.line++
		}
	}
	r.pos = end
}

// skip advances over the code points that match.
func (r *dotenvReader) skip(match func(rune) bool) int {
	end := r.pos
	for end < len(r.s) && match(r.s[end]) {
		end++
	}
	n := end - r.pos
	r.advanceTo(end)
	return n
}

// horizontalSpace is [^\S\r\n]: white space other than a line break.
func horizontalSpace(c rune) bool { return c != '\n' && c != '\r' && pyIsSpace(c) }

func notLineBreak(c rune) bool { return c != '\n' && c != '\r' }

// parseDotenvStatements is parse_stream for text that is already decoded,
// with universal newlines applied and the byte order mark removed.
func parseDotenvStatements(text string) []dotenvBinding {
	r := &dotenvReader{s: []rune(text), line: 1}
	var out []dotenvBinding
	for r.hasNext() {
		out = append(out, r.binding())
	}
	return out
}

// binding is parse_binding. A statement that does not match is skipped
// to the end of its line and reported.
func (r *dotenvReader) binding() dotenvBinding {
	line := r.line
	b, ok := r.statement()
	if !ok {
		// _rest_of_line: the rest of the line and its line break.
		r.skip(notLineBreak)
		if c := r.peek(); c == '\r' || c == '\n' {
			r.advanceTo(r.pos + 1)
		}
		return dotenvBinding{line: line, err: true}
	}
	b.line = line
	return b
}

func (r *dotenvReader) statement() (b dotenvBinding, ok bool) {
	r.skip(pyIsSpace)
	if !r.hasNext() {
		return b, true
	}
	r.export()
	if b.key, b.hasKey, ok = r.key(); !ok {
		return b, false
	}
	r.skip(horizontalSpace)
	if r.peek() == '=' {
		r.advanceTo(r.pos + 1)
		spaces := r.skip(horizontalSpace)
		// "KEY= # comment" is empty; "KEY=#x" keeps the "#".
		b.hasValue = true
		if spaces == 0 || r.peek() != '#' {
			if b.value, ok = r.value(); !ok {
				return b, false
			}
		}
	}
	r.comment()
	return b, r.endOfLine()
}

// export is (?:export[^\S\r\n]+)?.
func (r *dotenvReader) export() {
	const word = "export"
	end := r.pos + len(word)
	if end >= len(r.s) || string(r.s[r.pos:end]) != word || !horizontalSpace(r.s[end]) {
		return
	}
	r.advanceTo(end)
	r.skip(horizontalSpace)
}

// key is parse_key; ok is false where it raises.
func (r *dotenvReader) key() (key string, hasKey, ok bool) {
	switch r.peek() {
	case '#':
		return "", false, true
	case '\'':
		// '([^']+)'
		end := r.pos + 1
		for end < len(r.s) && r.s[end] != '\'' {
			end++
		}
		if end >= len(r.s) || end == r.pos+1 {
			return "", false, false
		}
		key = string(r.s[r.pos+1 : end])
		r.advanceTo(end + 1)
		return key, true, true
	}
	// ([^=\#\s]+)
	start := r.pos
	if r.skip(func(c rune) bool { return c != '=' && c != '#' && !pyIsSpace(c) }) == 0 {
		return "", false, false
	}
	return string(r.s[start:r.pos]), true, true
}

// value is parse_value; ok is false where it raises.
func (r *dotenvReader) value() (string, bool) {
	switch c := r.peek(); c {
	case '\'', '"':
		// '((?:\\.|[^'\\])*)' and its double-quoted twin, across lines.
		end := r.pos + 1
		for {
			if end >= len(r.s) {
				return "", false
			}
			if r.s[end] == '\\' {
				if end+1 >= len(r.s) {
					return "", false
				}
				end += 2
				continue
			}
			if r.s[end] == c {
				break
			}
			end++
		}
		raw := r.s[r.pos+1 : end]
		r.advanceTo(end + 1)
		return decodeDotenvEscapes(raw, c == '"'), true
	case -1, '\n', '\r':
		return "", true
	}
	start := r.pos
	r.skip(notLineBreak)
	return unquotedDotenvValue(r.s[start:r.pos]), true
}

// unquotedDotenvValue is parse_unquoted_value: re.sub(r"\s+#.*", "",
// part).rstrip(). The first run of white space followed by "#" starts the
// comment.
func unquotedDotenvValue(part []rune) string {
	cut := len(part)
	for i := 0; i < len(part); {
		if !pyIsSpace(part[i]) {
			i++
			continue
		}
		j := i
		for j < len(part) && pyIsSpace(part[j]) {
			j++
		}
		if j < len(part) && part[j] == '#' {
			cut = i
			break
		}
		i = j
	}
	return strings.TrimRightFunc(string(part[:cut]), pyIsSpace)
}

// decodeDotenvEscapes is decode_escapes with _double_quote_escapes or
// _single_quote_escapes: only the listed two-character escapes change.
func decodeDotenvEscapes(raw []rune, double bool) string {
	var b strings.Builder
	for i := 0; i < len(raw); i++ {
		if raw[i] == '\\' && i+1 < len(raw) {
			if d, ok := dotenvEscape(raw[i+1], double); ok {
				b.WriteRune(d)
				i++
				continue
			}
		}
		b.WriteRune(raw[i])
	}
	return b.String()
}

func dotenvEscape(c rune, double bool) (rune, bool) {
	switch c {
	case '\\', '\'':
		return c, true
	}
	if !double {
		return 0, false
	}
	switch c {
	case '"':
		return c, true
	case 'a':
		return '\a', true
	case 'b':
		return '\b', true
	case 'f':
		return '\f', true
	case 'n':
		return '\n', true
	case 'r':
		return '\r', true
	case 't':
		return '\t', true
	case 'v':
		return '\v', true
	}
	return 0, false
}

// comment is (?:[^\S\r\n]*#[^\r\n]*)?: it consumes nothing unless a "#"
// follows the white space.
func (r *dotenvReader) comment() {
	end := r.pos
	for end < len(r.s) && horizontalSpace(r.s[end]) {
		end++
	}
	if end < len(r.s) && r.s[end] == '#' {
		r.advanceTo(end)
		r.skip(notLineBreak)
	}
}

// endOfLine is [^\S\r\n]*(?:\r\n|\n|\r|$); false where it does not match.
func (r *dotenvReader) endOfLine() bool {
	r.skip(horizontalSpace)
	switch {
	case !r.hasNext():
	case r.peek() == '\r' && r.pos+1 < len(r.s) && r.s[r.pos+1] == '\n':
		r.advanceTo(r.pos + 2)
	case r.peek() == '\n' || r.peek() == '\r':
		r.advanceTo(r.pos + 1)
	default:
		return false
	}
	return true
}

// decodeDotenvText is open(path, encoding='utf-8').read() followed by
// removeprefix("\ufeff"): strict UTF-8, universal newlines.
func decodeDotenvText(data []byte) (string, error) {
	if !utf8.Valid(data) {
		return "", fmt.Errorf("the file is not valid UTF-8")
	}
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	return strings.TrimPrefix(text, "\ufeff"), nil
}

// parseDotenv returns what load_dotenv adds to an environment that lookup
// describes, in the order the variables are set, and the lines of the
// statements it could not parse.
func parseDotenv(data []byte, lookup LookupFunc) ([]EnvAssignment, []int, error) {
	text, err := decodeDotenvText(data)
	if err != nil {
		return nil, nil, err
	}
	var bad []int
	values := map[string]*string{}
	var order []string
	for _, b := range parseDotenvStatements(text) {
		if b.err {
			bad = append(bad, b.line)
		}
		if !b.hasKey {
			continue
		}
		var result *string
		if b.hasValue {
			v := interpolateDotenv(b.value, lookup, values)
			result = &v
		}
		if _, seen := values[b.key]; !seen {
			order = append(order, b.key)
		}
		values[b.key] = result
	}
	var out []EnvAssignment
	for _, name := range order {
		v := values[name]
		if _, set := lookup(name); set || v == nil {
			continue
		}
		// os.environ refuses these, which stops the Python release.
		if strings.ContainsAny(name, "=\x00") {
			return nil, bad, fmt.Errorf("the variable name %s cannot be set", pyRepr(name))
		}
		if strings.ContainsRune(*v, 0) {
			return nil, bad, fmt.Errorf("the value of %s contains a NUL character", name)
		}
		out = append(out, EnvAssignment{Name: name, Value: *v})
	}
	return out, bad, nil
}
