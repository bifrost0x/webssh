package legacy

import (
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"strconv"
	"strings"
)

// Number is a JSON number of a legacy store exactly as written. Python's
// json module reads integers with arbitrary precision and keeps them so
// when it writes the store back; float64 would round every integer above
// 2^53. A migration step converts a Number with Int64 or Float64 where the
// target needs a value, and copies the literal where it keeps the field
// verbatim.
type Number string

// Integer reports whether Python reads the literal as an int: no fraction
// and no exponent.
func (n Number) Integer() bool { return !strings.ContainsAny(string(n), ".eE") }

// Int64 returns the value of an integer literal that fits into int64.
func (n Number) Int64() (int64, bool) {
	if !n.Integer() {
		return 0, false
	}
	v, err := strconv.ParseInt(string(n), 10, 64)
	return v, err == nil
}

// Float64 returns the value as Python's float() would, for a literal
// Python reads as a float.
func (n Number) Float64() (float64, error) {
	return strconv.ParseFloat(string(n), 64)
}

// isZero is Python's "not value" for the number: 0, -0, 0.0 and 0e5 are
// false, every other value is true, however large.
func (n Number) isZero() bool {
	if n.Integer() {
		return strings.Trim(strings.TrimPrefix(string(n), "-"), "0") == ""
	}
	f, err := n.Float64()
	return err == nil && f == 0
}

// numbersAsText decodes every JSON number into an untyped value as a
// Number instead of a float64.
var numbersAsText = json.WithUnmarshalers(json.UnmarshalFromFunc(func(dec *jsontext.Decoder, v *any) error {
	if dec.PeekKind() != '0' {
		return errors.ErrUnsupported
	}
	tok, err := dec.ReadToken()
	if err != nil {
		return err
	}
	*v = Number(tok.String())
	return nil
}))
