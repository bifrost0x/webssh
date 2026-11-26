package hosts

import (
	"encoding/json/jsontext"
	"math"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// The rules of the Python release look at JSON values through Python's
// eyes: truthiness, str.strip(), int(), isprintable(). These helpers give
// the same answers for the values a decoded payload can hold.

// truthy is Python's bool() of a decoded JSON value.
func truthy(v jsontext.Value) bool {
	switch v.Kind() {
	case 0, 'n', 'f':
		return false
	case 't':
		return true
	case '"':
		s, _ := asString(v)
		return s != ""
	case '0':
		// Out of range gives ±Inf (not zero, like a huge Python int) or
		// 0 for an underflow (0.0 in Python).
		f, _ := strconv.ParseFloat(string(v), 64)
		return f != 0
	case '[':
		return string(v) != "[]"
	case '{':
		return string(v) != "{}"
	}
	return true
}

// pyIsSpace is str.isspace() for one character: Unicode white space plus
// the four ASCII separators Python counts as space.
func pyIsSpace(r rune) bool {
	switch r {
	case 0x1c, 0x1d, 0x1e, 0x1f:
		return true
	}
	return unicode.IsSpace(r) || unicode.Is(unicode.Zs, r)
}

// pyStrip is str.strip() without arguments.
func pyStrip(s string) string { return strings.TrimFunc(s, pyIsSpace) }

// pyLen is len() of a Python str: code points.
func pyLen(s string) int { return utf8.RuneCountInString(s) }

// pyPrefix is s[:n] for a Python str.
func pyPrefix(s string, n int) string {
	i := 0
	for count := 0; i < len(s) && count < n; count++ {
		_, size := utf8.DecodeRuneInString(s[i:])
		i += size
	}
	return s[:i]
}

// pyPrintable is str.isprintable() for one character. Go's IsPrint has the
// same definition (letters, marks, numbers, punctuation, symbols and the
// ASCII space); the Unicode versions of the two runtimes may differ for
// characters assigned recently.
func pyPrintable(r rune) bool { return unicode.IsPrint(r) }

// safeReferenceMaxBytes is SAFE_REFERENCE_MAX_BYTES of app/storage_utils.py.
const safeReferenceMaxBytes = 128

// safeReferenceName is safe_reference_name: printable text within 128
// UTF-8 bytes, a cut character dropped.
func safeReferenceName(value string) string {
	var b strings.Builder
	for _, r := range value {
		if !pyPrintable(r) {
			r = unicode.ReplacementChar
		}
		b.WriteRune(r)
	}
	out := b.String()
	if len(out) <= safeReferenceMaxBytes {
		return out
	}
	out = out[:safeReferenceMaxBytes]
	for !utf8.ValidString(out) {
		out = out[:len(out)-1]
	}
	return out
}

// pyInt is int() of a decoded JSON value as the port parsers use it. ok is
// false where Python raises ValueError or TypeError (or an OverflowError
// the callers do not expect, which they report the same way).
func pyInt(v jsontext.Value) (n int64, ok bool) {
	switch v.Kind() {
	case 't':
		return 1, true
	case 'f':
		return 0, true
	case '0':
		if i, ok := asInt(v); ok {
			return i, true
		}
		if isIntegerToken(v) {
			// Beyond int64: every caller checks a small range.
			if strings.HasPrefix(string(v), "-") {
				return math.MinInt64, true
			}
			return math.MaxInt64, true
		}
		f, err := strconv.ParseFloat(string(v), 64)
		if err != nil || math.IsInf(f, 0) {
			return 0, false
		}
		return int64(math.Trunc(math.Max(math.Min(f, math.MaxInt64), math.MinInt64))), true
	case '"':
		s, _ := asString(v)
		return pyIntString(s)
	}
	return 0, false
}

// pyIntString is int(str) for base 10 with ASCII digits: surrounding white
// space, an optional sign and single underscores between digits.
func pyIntString(s string) (int64, bool) {
	s = pyStrip(s)
	neg := false
	if s != "" && (s[0] == '+' || s[0] == '-') {
		neg = s[0] == '-'
		s = s[1:]
	}
	if s == "" || s[0] == '_' || s[len(s)-1] == '_' || strings.Contains(s, "__") {
		return 0, false
	}
	var n int64
	for i := range len(s) {
		c := s[i]
		if c == '_' {
			continue
		}
		if c < '0' || c > '9' {
			return 0, false
		}
		if n > (math.MaxInt64-9)/10 {
			n = math.MaxInt64 // saturate: only the range matters
			continue
		}
		n = n*10 + int64(c-'0')
	}
	if neg {
		n = -n
	}
	return n, true
}

// isIntegerToken reports a JSON number without fraction or exponent.
func isIntegerToken(v jsontext.Value) bool {
	return v.Kind() == '0' && !strings.ContainsAny(string(v), ".eE")
}

// sortOrderValid is _valid_sort_order: an integer of at least zero.
func sortOrderValid(v jsontext.Value) bool {
	return isIntegerToken(v) && (!strings.HasPrefix(string(v), "-") || strings.Trim(string(v), "-0") == "")
}

// compareSortOrder orders two valid sort orders numerically without a size
// limit: JSON integers have no leading zeros.
func compareSortOrder(a, b jsontext.Value) int {
	as, bs := strings.TrimPrefix(string(a), "-"), strings.TrimPrefix(string(b), "-")
	if len(as) != len(bs) {
		return len(as) - len(bs)
	}
	return strings.Compare(as, bs)
}

// isoUTC is datetime.now(timezone.utc).isoformat().
func isoUTC(t time.Time) string { return isoNaive(t) + "+00:00" }

// isoNaive is datetime.now(timezone.utc).replace(tzinfo=None).isoformat():
// the fraction appears only when there are microseconds.
func isoNaive(t time.Time) string {
	t = t.UTC().Truncate(time.Microsecond)
	if t.Nanosecond() == 0 {
		return t.Format("2006-01-02T15:04:05")
	}
	return t.Format("2006-01-02T15:04:05.000000")
}
