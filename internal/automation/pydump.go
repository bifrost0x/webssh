package automation

import (
	"encoding/json/jsontext"
	"math"
	"slices"
	"strconv"
	"strings"

	"github.com/bifrost0x/webssh/internal/pyjson"
)

// dumpOptions are the json.dumps arguments the Python release used.
type dumpOptions struct {
	indent   int  // 0: one line with ", " and ": " (json.dumps default)
	sortKeys bool // digest(): sort_keys with ","/":" separators
}

// pyDump writes v as Python's json.dumps(v, ensure_ascii=True) with the
// options: string escapes of ensure_ascii, number texts as Python prints
// the parsed value, member order kept unless sorted. v must be valid,
// strict JSON (pyjson.Load output or built by this package).
func pyDump(v jsontext.Value, o dumpOptions) string {
	var b strings.Builder
	dumpValue(&b, v, o, 0)
	return b.String()
}

func dumpValue(b *strings.Builder, v jsontext.Value, o dumpOptions, depth int) {
	switch v.Kind() {
	case '"':
		s, _ := unquote(v)
		b.WriteString(pyjson.Quote(s))
	case '0':
		b.WriteString(pyNumber(string(v)))
	case '[':
		items, _ := pyjson.Items(v)
		if len(items) == 0 {
			b.WriteString("[]")
			return
		}
		b.WriteByte('[')
		for i, item := range items {
			separate(b, o, i, depth+1)
			dumpValue(b, item, o, depth+1)
		}
		closeLine(b, o, depth)
		b.WriteByte(']')
	case '{':
		members, _ := pyjson.Members(v)
		if len(members) == 0 {
			b.WriteString("{}")
			return
		}
		if o.sortKeys {
			members = slices.Clone(members)
			slices.SortStableFunc(members, func(a, c pyjson.Member) int { return compareCodePoints(a.Name, c.Name) })
		}
		b.WriteByte('{')
		for i, m := range members {
			separate(b, o, i, depth+1)
			b.WriteString(pyjson.Quote(m.Name))
			if o.sortKeys {
				b.WriteByte(':')
			} else {
				b.WriteString(": ")
			}
			dumpValue(b, m.Value, o, depth+1)
		}
		closeLine(b, o, depth)
		b.WriteByte('}')
	default:
		b.Write(v)
	}
}

func separate(b *strings.Builder, o dumpOptions, i, depth int) {
	switch {
	case o.indent > 0:
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteByte('\n')
		b.WriteString(strings.Repeat(" ", o.indent*depth))
	case i == 0:
	case o.sortKeys:
		b.WriteByte(',')
	default:
		b.WriteString(", ")
	}
}

func closeLine(b *strings.Builder, o dumpOptions, depth int) {
	if o.indent > 0 {
		b.WriteByte('\n')
		b.WriteString(strings.Repeat(" ", o.indent*depth))
	}
}

// compareCodePoints orders member names as Python sorts str keys: by
// code point.
func compareCodePoints(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	return slices.Compare(ra, rb)
}

func unquote(v jsontext.Value) (string, bool) {
	dec := jsontext.NewDecoder(strings.NewReader(string(v)))
	tok, err := dec.ReadToken()
	if err != nil || tok.Kind() != '"' {
		return "", false
	}
	return tok.String(), true
}

// pyNumber is the text Python prints for a parsed JSON number: integers
// in their decimal form, floats as repr.
func pyNumber(text string) string {
	if !strings.ContainsAny(text, ".eE") {
		n, err := strconv.ParseInt(text, 10, 64)
		if err != nil {
			return text // beyond int64: Python keeps the digits
		}
		return strconv.FormatInt(n, 10)
	}
	f, err := strconv.ParseFloat(text, 64)
	if err != nil && !math.IsInf(f, 0) {
		return text
	}
	return pyFloat(f)
}

// pyFloat is repr() of a Python float.
func pyFloat(f float64) string {
	switch {
	case math.IsInf(f, 1):
		return "Infinity"
	case math.IsInf(f, -1):
		return "-Infinity"
	case math.IsNaN(f):
		return "NaN"
	}
	if f == 0 {
		if math.Signbit(f) {
			return "-0.0"
		}
		return "0.0"
	}
	e := strconv.FormatFloat(f, 'e', -1, 64) // d.ddde±XX
	mant, expText, _ := strings.Cut(e, "e")
	exp, _ := strconv.Atoi(expText)
	neg := strings.HasPrefix(mant, "-")
	mant = strings.TrimPrefix(mant, "-")
	digits := strings.Replace(mant, ".", "", 1)
	var out string
	if exp < -4 || exp >= 16 {
		out = digits[:1]
		if len(digits) > 1 {
			out += "." + digits[1:]
		}
		sign := "+"
		if exp < 0 {
			sign, exp = "-", -exp
		}
		out += "e" + sign + strconv.Itoa(exp/10) + strconv.Itoa(exp%10)
		if exp >= 100 {
			out = out[:len(out)-2] + strconv.Itoa(exp)
		}
	} else if exp >= 0 {
		if len(digits) <= exp+1 {
			out = digits + strings.Repeat("0", exp+1-len(digits)) + ".0"
		} else {
			out = digits[:exp+1] + "." + digits[exp+1:]
		}
	} else {
		out = "0." + strings.Repeat("0", -exp-1) + digits
	}
	if neg {
		out = "-" + out
	}
	return out
}
