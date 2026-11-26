package config

import (
	"math/big"
	"strings"
	"unicode"
	"unicode/utf8"
)

// The helpers in this file reproduce the Python string operations that the
// Python release applies to environment values. They exist so that every
// value keeps the meaning it has today (decision D-14); the tests compare
// them with CPython.

// pyIsSpace reports whether Python's str.isspace() is true for r. Python
// also counts the information separators U+001C to U+001F, which Go's
// unicode.IsSpace does not.
func pyIsSpace(r rune) bool {
	return unicode.IsSpace(r) || r >= 0x1c && r <= 0x1f
}

// pyStrip is Python's str.strip() without arguments.
func pyStrip(s string) string {
	return strings.TrimFunc(s, pyIsSpace)
}

// pyLower is Python's str.lower(). Python applies the full lower-case
// mapping, which differs from the simple mapping for U+0130 (capital I
// with dot above becomes "i" plus a combining dot) and for the capital
// sigma at the end of a word, which becomes the final sigma.
func pyLower(s string) string {
	if isASCII(s) {
		return strings.ToLower(s)
	}
	rs := []rune(s)
	var b strings.Builder
	b.Grow(len(s))
	for i, r := range rs {
		switch r {
		case '\u0130':
			b.WriteString("i\u0307")
		case '\u03a3':
			if finalSigma(rs, i) {
				b.WriteRune('\u03c2')
			} else {
				b.WriteRune('\u03c3')
			}
		default:
			b.WriteRune(unicode.ToLower(r))
		}
	}
	return b.String()
}

// finalSigma is the Final_Sigma condition as CPython tests it: a cased
// letter, then case-ignorable characters, then the sigma, and no cased
// letter after further case-ignorable characters.
func finalSigma(rs []rune, i int) bool {
	j := i - 1
	for j >= 0 && caseIgnorable(rs[j]) {
		j--
	}
	if j < 0 || !cased(rs[j]) {
		return false
	}
	j = i + 1
	for j < len(rs) && caseIgnorable(rs[j]) {
		j++
	}
	return j == len(rs) || !cased(rs[j])
}

// caseIgnorableMarks are the characters with Word_Break MidLetter,
// MidNumLet or Single_Quote, which are case-ignorable besides the general
// categories below. The set matches CPython 3.15 (Unicode 17) exactly.
var caseIgnorableMarks = map[rune]bool{
	0x27: true, 0x2E: true, 0x3A: true, 0xB7: true, 0x387: true, 0x55F: true,
	0x5F4: true, 0x2018: true, 0x2019: true, 0x2024: true, 0x2027: true,
	0xFE13: true, 0xFE52: true, 0xFE55: true, 0xFF07: true, 0xFF0E: true, 0xFF1A: true,
}

func caseIgnorable(r rune) bool {
	return caseIgnorableMarks[r] || unicode.In(r, unicode.Mn, unicode.Me, unicode.Cf, unicode.Lm, unicode.Sk)
}

func cased(r rune) bool {
	return unicode.In(r, unicode.Lu, unicode.Ll, unicode.Lt, unicode.Other_Lowercase, unicode.Other_Uppercase)
}

func isASCII(s string) bool {
	for i := range len(s) {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// isASCIIDigits is Python's s.isascii() and s.isdigit(): non-empty and only
// the digits 0 to 9.
func isASCIIDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := range len(s) {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// pyIsTrue is the bool parser of the Python release:
// value.lower() == 'true', without stripping.
func pyIsTrue(s string) bool {
	return pyLower(s) == "true"
}

// pyMaxStrDigits is CPython's default limit for converting a decimal
// string to an int (sys.int_info.str_digits_check_threshold applies above
// 640 digits; the default limit is 4300).
const pyMaxStrDigits = 4300

// pyInt parses s like Python's int(s) (CPython's
// _PyUnicode_TransformDecimalAndSpaceToASCII and PyLong_FromString):
// surrounding white space, a sign,
// single underscores between digits and every Unicode decimal digit are
// accepted. ok is false where Python raises ValueError.
func pyInt(s string) (v *big.Int, ok bool) {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r < 127:
			b.WriteRune(r)
		case pyIsSpace(r):
			b.WriteByte(' ')
		default:
			d, isDigit := decimalValue(r)
			if !isDigit {
				return nil, false
			}
			b.WriteByte("0123456789"[d])
		}
	}
	// CPython skips only the ASCII white space of C's isspace() here; the
	// other characters Python counts as white space became ' ' above.
	t := strings.Trim(b.String(), " \t\n\v\f\r")
	negative := false
	if t != "" && (t[0] == '+' || t[0] == '-') {
		negative = t[0] == '-'
		t = t[1:]
	}
	if t == "" || t[0] == '_' || t[len(t)-1] == '_' {
		return nil, false
	}
	digits := make([]byte, 0, len(t))
	for i := range len(t) {
		c := t[i]
		switch {
		case c >= '0' && c <= '9':
			digits = append(digits, c)
		case c == '_' && t[i-1] != '_':
		default:
			return nil, false
		}
	}
	if len(digits) > pyMaxStrDigits {
		return nil, false
	}
	v, _ = new(big.Int).SetString(string(digits), 10)
	if negative {
		v.Neg(v)
	}
	return v, true
}

// canonicalInt reports whether s is already written the way Go and most
// tools expect an integer: ASCII digits with an optional minus sign and no
// leading zeros.
func canonicalInt(s string, v *big.Int) bool {
	return s == v.String()
}

// decimalValue returns the value of a Unicode decimal digit (general
// category Nd). Unicode assigns decimal digits in contiguous runs of ten,
// starting with zero, so the value follows from the start of the run.
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

// pyCSV splits like the Python release's comprehension
// [v.strip() for v in raw.split(',') if v.strip()].
func pyCSV(raw string) []string {
	var out []string
	for part := range strings.SplitSeq(raw, ",") {
		if v := pyStrip(part); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// pyCSVSet is pyCSV with duplicates removed, like the frozenset of
// _csv_env. The order of first appearance is kept.
func pyCSVSet(raw string, normalize func(string) string) []string {
	var out []string
	seen := map[string]bool{}
	for _, v := range pyCSV(raw) {
		if normalize != nil {
			v = normalize(v)
		}
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

// truncateRunes keeps the first n code points, like s[:n] in Python.
func truncateRunes(s string, n int) string {
	i := 0
	for pos := range s {
		if i == n {
			return s[:pos]
		}
		i++
	}
	return s
}

// runeLen counts code points, like len(s) in Python. An invalid UTF-8
// byte counts as one, as it does for a string decoded with
// surrogateescape.
func runeLen(s string) int { return utf8.RuneCountInString(s) }
