package commands

import (
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/bifrost0x/webssh/internal/pyjson"
)

// The requests and the stored records are read as Python's dict and list
// values: decoded into any, so the rules of the Python release can test
// presence and type as it did (isinstance, truthiness).

// decode turns a raw member into a value; an absent member (zero length)
// is absent.
func decode(v jsontext.Value) (any, bool) {
	if len(v) == 0 {
		return nil, false
	}
	var out any
	if err := json.Unmarshal(v, &out); err != nil {
		return nil, false
	}
	return out, true
}

// truthy is Python's bool() of a decoded JSON value.
func truthy(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case bool:
		return t
	case float64:
		return t != 0
	case string:
		return t != ""
	case []any:
		return len(t) > 0
	case map[string]any:
		return len(t) > 0
	}
	return true
}

// rawString encodes a string member of a record.
func rawString(s string) jsontext.Value { return pyjson.String(s) }

// rawValue encodes a decoded value; it never fails for decoded JSON.
func rawValue(v any) jsontext.Value {
	out, err := json.Marshal(v, json.Deterministic(true))
	if err != nil {
		return jsontext.Value("null")
	}
	return out
}

// pyPrintable is str.isprintable for one code point: not a control,
// format, surrogate, private-use or unassigned character and no separator
// other than the space.
func pyPrintable(r rune) bool {
	if r == ' ' {
		return true
	}
	if unicode.In(r, unicode.Cc, unicode.Cf, unicode.Cs, unicode.Co, unicode.Zs, unicode.Zl, unicode.Zp) {
		return false
	}
	return unicode.IsPrint(r) || unicode.In(r, unicode.L, unicode.M, unicode.N, unicode.P, unicode.S)
}

// safeReferenceName is safe_reference_name: printable text within 128
// bytes of UTF-8, cut at a character boundary.
func safeReferenceName(v any) string {
	s, _ := v.(string)
	var b strings.Builder
	for _, r := range s {
		if !pyPrintable(r) {
			r = utf8.RuneError
		}
		if b.Len()+utf8.RuneLen(r) > 128 {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}

// fold is the case-insensitive comparison of set names (str.casefold),
// with the full folds of the characters a name is likely to hold.
func fold(s string) string {
	return strings.NewReplacer("ß", "ss", "ẞ", "ss", "ς", "σ").Replace(strings.ToLower(s))
}
