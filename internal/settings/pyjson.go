package settings

import (
	"encoding/json/jsontext"
	"errors"
	"math"
	"slices"
	"strconv"
	"strings"
)

// errEncode marks a value the Python encoding cannot represent here.
var errEncode = errors.New("settings: value cannot be encoded")

// PythonJSON encodes a JSON value as the Jinja filter tojson of the
// Python release writes it into a page: json.dumps with sorted keys,
// the separators ", " and ": ", ASCII only, and <, >, & and ' as \u
// escapes. Pages and end-to-end tests read these blocks as text, so the
// bytes must match. Numbers are written as Python writes the int or float
// json.loads makes of them. A float that overflows is an error: the
// callers pass validated values only and fail closed.
func PythonJSON(v jsontext.Value) (string, error) {
	var b strings.Builder
	if err := writePython(&b, v, 0); err != nil {
		return "", err
	}
	return b.String(), nil
}

// maxPythonDepth bounds the nesting of encoded values.
const maxPythonDepth = 64

func writePython(b *strings.Builder, v jsontext.Value, depth int) error {
	if depth > maxPythonDepth {
		return errEncode
	}
	switch v.Kind() {
	case 'n':
		b.WriteString("null")
	case 't':
		b.WriteString("true")
	case 'f':
		b.WriteString("false")
	case '"':
		s, ok := asString(v)
		if !ok {
			return errEncode
		}
		writePythonString(b, s)
	case '0':
		return writePythonNumber(b, string(v))
	case '[':
		items, ok := asArray(v)
		if !ok {
			return errEncode
		}
		b.WriteByte('[')
		for i, item := range items {
			if i > 0 {
				b.WriteString(", ")
			}
			if err := writePython(b, item, depth+1); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case '{':
		members, ok := asObject(v)
		if !ok {
			return errEncode
		}
		slices.SortFunc(members, func(x, y member) int { return strings.Compare(x.name, y.name) })
		b.WriteByte('{')
		for i, m := range members {
			if i > 0 {
				b.WriteString(", ")
			}
			writePythonString(b, m.name)
			b.WriteString(": ")
			if err := writePython(b, m.value, depth+1); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		return errEncode
	}
	return nil
}

const hexDigits = "0123456789abcdef"

func writePythonString(b *strings.Builder, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '<', '>', '&', '\'':
			writeUnicodeEscape(b, r)
		default:
			switch {
			case r >= 0x20 && r < 0x7f:
				b.WriteRune(r)
			case r > 0xffff:
				r -= 0x10000
				writeUnicodeEscape(b, 0xd800+(r>>10))
				writeUnicodeEscape(b, 0xdc00+(r&0x3ff))
			default:
				writeUnicodeEscape(b, r)
			}
		}
	}
	b.WriteByte('"')
}

func writeUnicodeEscape(b *strings.Builder, r rune) {
	b.WriteString(`\u`)
	for shift := 12; shift >= 0; shift -= 4 {
		b.WriteByte(hexDigits[(r>>shift)&0xf])
	}
}

// writePythonNumber writes an integer token unchanged (Python ints are
// exact; "-0" becomes 0) and a float with Python's repr.
func writePythonNumber(b *strings.Builder, tok string) error {
	if !strings.ContainsAny(tok, ".eE") {
		if strings.TrimLeft(tok, "-0") == "" {
			tok = "0"
		}
		b.WriteString(tok)
		return nil
	}
	f, err := strconv.ParseFloat(tok, 64)
	if err != nil || math.IsInf(f, 0) {
		return errEncode
	}
	b.WriteString(pythonFloatRepr(f))
	return nil
}

// pythonFloatRepr is repr(float): the shortest digits that round-trip,
// in positional form for decimal exponents from -4 to 15 with at least one
// fractional digit, otherwise in exponent form with at least two exponent
// digits.
func pythonFloatRepr(f float64) string {
	e := strconv.FormatFloat(f, 'e', -1, 64) // [-]d[.ddd]e±XX
	sign := ""
	if e[0] == '-' {
		sign, e = "-", e[1:]
	}
	mantissa, expText, _ := strings.Cut(e, "e")
	exp, _ := strconv.Atoi(expText)
	if exp < -4 || exp >= 16 {
		return sign + e
	}
	digits := strings.Replace(mantissa, ".", "", 1)
	var out string
	switch point := exp + 1; {
	case point <= 0:
		out = "0." + strings.Repeat("0", -point) + digits
	case point >= len(digits):
		out = digits + strings.Repeat("0", point-len(digits)) + ".0"
	default:
		out = digits[:point] + "." + digits[point:]
	}
	return sign + out
}
