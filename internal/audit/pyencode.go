package audit

import (
	"math"
	"slices"
	"strconv"
	"strings"
	"unicode"
)

// encoding is one set of json.dumps options.
type encoding struct {
	compact     bool // separators (",", ":") instead of (", ", ": ")
	ensureASCII bool
	sortKeys    bool
	nanAsNull   bool // NaN and the infinities as null (a fix for the view)
}

var (
	// exportLine is json.dumps(record, ensure_ascii=False, separators=(",", ":")).
	exportLine = encoding{compact: true}
	// queryText is json.dumps(record, ensure_ascii=False), the text the
	// export's search matches.
	queryText = encoding{}
	// viewJSON is Flask's jsonify: ASCII, sorted keys, compact.
	viewJSON = encoding{compact: true, ensureASCII: true, sortKeys: true, nanAsNull: true}
)

func (e encoding) encode(b *strings.Builder, v value) {
	switch v.kind {
	case kindNull:
		b.WriteString("null")
	case kindBool:
		b.WriteString(strconv.FormatBool(v.b))
	case kindInt:
		b.WriteString(v.num)
	case kindFloat:
		s := floatRepr(v.f)
		if e.nanAsNull && (math.IsNaN(v.f) || math.IsInf(v.f, 0)) {
			s = "null"
		}
		b.WriteString(s)
	case kindString:
		e.str(b, v.str)
	case kindArray:
		b.WriteByte('[')
		for i, item := range v.items {
			if i > 0 {
				e.sep(b, ',')
			}
			e.encode(b, item)
		}
		b.WriteByte(']')
	case kindObject:
		order := make([]int, len(v.keys))
		for i := range order {
			order[i] = i
		}
		if e.sortKeys {
			slices.SortStableFunc(order, func(x, y int) int { return slices.Compare(v.keys[x], v.keys[y]) })
		}
		b.WriteByte('{')
		for n, i := range order {
			if n > 0 {
				e.sep(b, ',')
			}
			e.str(b, v.keys[i])
			e.sep(b, ':')
			e.encode(b, v.vals[i])
		}
		b.WriteByte('}')
	}
}

func (e encoding) sep(b *strings.Builder, c byte) {
	b.WriteByte(c)
	if !e.compact {
		b.WriteByte(' ')
	}
}

// str writes a string as json.dumps does. Without ensure_ascii a lone
// surrogate is still escaped: Python wrote it raw and the response then
// failed to encode (fix).
func (e encoding) str(b *strings.Builder, rs []rune) {
	b.WriteByte('"')
	for _, r := range rs {
		switch {
		case r == '"':
			b.WriteString(`\"`)
		case r == '\\':
			b.WriteString(`\\`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r == '\b':
			b.WriteString(`\b`)
		case r == '\f':
			b.WriteString(`\f`)
		case r < 0x20, r >= 0xd800 && r <= 0xdfff:
			writeU(b, r)
		case e.ensureASCII && r > 0x7e:
			if r > 0xffff {
				writeU(b, 0xd800+(r-0x10000)>>10)
				writeU(b, 0xdc00+(r-0x10000)&0x3ff)
			} else {
				writeU(b, r)
			}
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
}

// floatRepr is Python's repr(float) as json.dumps writes it: the
// shortest round-trip digits, positional between 1e-4 and 1e16 with at
// least one fractional digit, otherwise scientific with a two-digit
// exponent.
func floatRepr(f float64) string {
	switch {
	case math.IsNaN(f):
		return "NaN"
	case math.IsInf(f, 1):
		return "Infinity"
	case math.IsInf(f, -1):
		return "-Infinity"
	}
	s := strconv.FormatFloat(f, 'e', -1, 64) // d.ddde±XX
	sign := ""
	if s[0] == '-' {
		sign, s = "-", s[1:]
	}
	mant, expText, _ := strings.Cut(s, "e")
	exp, _ := strconv.Atoi(expText)
	ds := strings.Replace(mant, ".", "", 1)
	if exp < -4 || exp >= 16 {
		m := ds[:1]
		if len(ds) > 1 {
			m += "." + ds[1:]
		}
		es := "+"
		if exp < 0 {
			es, exp = "-", -exp
		}
		e := strconv.Itoa(exp)
		if len(e) < 2 {
			e = "0" + e
		}
		return sign + m + "e" + es + e
	}
	if exp < 0 {
		return sign + "0." + strings.Repeat("0", -exp-1) + ds
	}
	if len(ds) <= exp+1 {
		return sign + ds + strings.Repeat("0", exp+1-len(ds)) + ".0"
	}
	return sign + ds[:exp+1] + "." + ds[exp+1:]
}

// pyLower is Python's str.lower for matching: the full lower-case
// mapping, where U+0130 becomes "i̇", and the final sigma rule applied to
// letters on either side.
func pyLower(rs []rune) []rune {
	out := make([]rune, 0, len(rs))
	for i, r := range rs {
		switch r {
		case 0x130:
			out = append(out, 'i', 0x307)
		case 0x3a3:
			before := i > 0 && unicode.IsLetter(rs[i-1])
			after := i+1 < len(rs) && unicode.IsLetter(rs[i+1])
			if before && !after {
				out = append(out, 0x3c2)
			} else {
				out = append(out, 0x3c3)
			}
		default:
			out = append(out, unicode.ToLower(r))
		}
	}
	return out
}

// pyUpper is str.upper for the level filter; levels are ASCII names, so
// the simple mapping is enough.
func pyUpper(s string) string { return strings.ToUpper(s) }

// containsRunes reports whether needle occurs in hay.
func containsRunes(hay, needle []rune) bool {
	if len(needle) == 0 {
		return true
	}
	for i := 0; i+len(needle) <= len(hay); i++ {
		if slices.Equal(hay[i:i+len(needle)], needle) {
			return true
		}
	}
	return false
}

// pyStrOf is str(value) for the level filter. Containers have no level
// name and never match (Python compared their repr).
func pyStrOf(v value) (string, bool) {
	switch v.kind {
	case kindString:
		return string(v.str), true
	case kindNull:
		return "None", true
	case kindBool:
		if v.b {
			return "True", true
		}
		return "False", true
	case kindInt:
		return v.num, true
	case kindFloat:
		s := floatRepr(v.f)
		switch s {
		case "NaN":
			s = "nan"
		case "Infinity":
			s = "inf"
		case "-Infinity":
			s = "-inf"
		}
		return s, true
	}
	return "", false
}
