package hostops

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// The helpers in this file reproduce the Python string operations the
// parsers of the Python release apply to remote output, so a sample keeps
// its meaning; the differential tests compare them with CPython. Numbers
// are the exception: only plain ASCII decimals are accepted (numbers.go).

// pyIsSpace is str.isspace() for one character.
func pyIsSpace(r rune) bool {
	return unicode.IsSpace(r) || r >= 0x1c && r <= 0x1f
}

// pyStrip is str.strip() without arguments.
func pyStrip(s string) string { return strings.TrimFunc(s, pyIsSpace) }

// pyLineBreak reports the characters str.splitlines() splits on, except
// "\r\n", which splitLines handles.
func pyLineBreak(r rune) bool {
	switch r {
	case '\n', '\r', '\v', '\f', 0x1c, 0x1d, 0x1e, 0x85, 0x2028, 0x2029:
		return true
	}
	return false
}

// splitLines is str.splitlines().
func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if !pyLineBreak(r) {
			i += size
			continue
		}
		out = append(out, s[start:i])
		i += size
		if r == '\r' && i < len(s) && s[i] == '\n' {
			i++
		}
		start = i
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

// splitFields is str.split(None, maxsplit): fields separated by runs of
// white space, at most maxsplit splits; the rest keeps its trailing white
// space.
func splitFields(s string, maxsplit int) []string {
	var out []string
	s = strings.TrimLeftFunc(s, pyIsSpace)
	for s != "" {
		if len(out) == maxsplit {
			return append(out, s)
		}
		end := strings.IndexFunc(s, pyIsSpace)
		if end < 0 {
			return append(out, s)
		}
		out = append(out, s[:end])
		s = strings.TrimLeftFunc(s[end:], pyIsSpace)
	}
	return out
}

// pyPrintable is str.isprintable() for one character: letters, marks,
// numbers, punctuation, symbols and the ASCII space.
func pyPrintable(r rune) bool { return unicode.IsPrint(r) }

// hasControl reports a character below U+0020 or U+007F, which the
// parsers refuse in remote text.
func hasControl(s string) bool {
	return strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f })
}

// runeLen is len() of a Python str.
func runeLen(s string) int { return utf8.RuneCountInString(s) }

// decodeReplace is bytes.decode("utf-8", "replace"): every maximal
// invalid subsequence becomes one U+FFFD, as CPython does.
func decodeReplace(b []byte) string {
	if utf8.Valid(b) {
		return string(b)
	}
	var out strings.Builder
	out.Grow(len(b) + 8)
	for i := 0; i < len(b); {
		r, size := utf8.DecodeRune(b[i:])
		if r != utf8.RuneError || size > 1 {
			out.WriteRune(r)
			i += size
			continue
		}
		out.WriteRune(utf8.RuneError)
		i += invalidPrefix(b[i:])
	}
	return out.String()
}

// invalidPrefix is the length of the maximal subpart of an ill-formed
// sequence at the start of b (Unicode 3.9, table 3-7): a lead byte and the
// continuation bytes that could still have completed it.
func invalidPrefix(b []byte) int {
	lead := b[0]
	var need int
	lo, hi := byte(0x80), byte(0xbf)
	switch {
	case lead >= 0xc2 && lead <= 0xdf:
		need = 1
	case lead == 0xe0:
		need, lo = 2, 0xa0
	case lead >= 0xe1 && lead <= 0xec, lead == 0xee, lead == 0xef:
		need = 2
	case lead == 0xed:
		need, hi = 2, 0x9f
	case lead == 0xf0:
		need, lo = 3, 0x90
	case lead >= 0xf1 && lead <= 0xf3:
		need = 3
	case lead == 0xf4:
		need, hi = 3, 0x8f
	default:
		return 1
	}
	n := 1
	for n <= need && n < len(b) {
		c := b[n]
		if c < lo || c > hi {
			break
		}
		lo, hi = 0x80, 0xbf
		n++
	}
	return n
}

// displayText is the server operations' _display: the output decoded
// with replacement, keeping printable characters, newline and tab.
func displayText(b []byte) string {
	s := decodeReplace(b)
	return strings.Map(func(r rune) rune {
		if pyPrintable(r) || r == '\n' || r == '\t' {
			return r
		}
		return -1
	}, s)
}
