package settings

import (
	"bytes"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"math"
	"strconv"
)

// These helpers read one JSON value the way the Python release sees it
// after json.loads: integers (no fraction, no exponent) and floats are
// different types, booleans are not numbers, null is None.

func isNull(v jsontext.Value) bool { return v.Kind() == 'n' }

func asString(v jsontext.Value) (string, bool) {
	if v.Kind() != '"' {
		return "", false
	}
	var s string
	if json.Unmarshal(v, &s) != nil {
		return "", false
	}
	return s, true
}

func asBool(v jsontext.Value) (value, ok bool) {
	switch v.Kind() {
	case 't':
		return true, true
	case 'f':
		return false, true
	}
	return false, false
}

// isIntToken reports a JSON number without fraction and exponent, which
// Python reads as int.
func isIntToken(v jsontext.Value) bool {
	return v.Kind() == '0' && !bytes.ContainsAny(v, ".eE")
}

// asInt returns a Python int that fits int64; larger integers are outside
// every range this package accepts.
func asInt(v jsontext.Value) (int64, bool) {
	if !isIntToken(v) {
		return 0, false
	}
	n, err := strconv.ParseInt(string(bytes.TrimSpace(v)), 10, 64)
	return n, err == nil
}

// asFinite returns an int or float that is finite as a float64. Python
// turns an overflowing float literal into inf, which the callers reject.
func asFinite(v jsontext.Value) (float64, bool) {
	if v.Kind() != '0' {
		return 0, false
	}
	f, err := strconv.ParseFloat(string(bytes.TrimSpace(v)), 64)
	if err != nil || math.IsInf(f, 0) || math.IsNaN(f) {
		return 0, false
	}
	return f, true
}

// member is one name and value of a JSON object, in document order.
type member struct {
	name  string
	value jsontext.Value
}

// asObject returns the members of an object. Duplicate names are
// rejected (encoding/json/v2 default).
func asObject(v jsontext.Value) ([]member, bool) {
	if v.Kind() != '{' {
		return nil, false
	}
	dec := jsontext.NewDecoder(bytes.NewReader(v))
	if _, err := dec.ReadToken(); err != nil {
		return nil, false
	}
	var out []member
	for dec.PeekKind() != '}' {
		tok, err := dec.ReadToken()
		if err != nil {
			return nil, false
		}
		name := tok.String()
		val, err := dec.ReadValue()
		if err != nil {
			return nil, false
		}
		out = append(out, member{name: name, value: val.Clone()})
	}
	return out, true
}

// asArray returns the items of an array.
func asArray(v jsontext.Value) ([]jsontext.Value, bool) {
	if v.Kind() != '[' {
		return nil, false
	}
	var items []jsontext.Value
	if json.Unmarshal(v, &items) != nil {
		return nil, false
	}
	return items, true
}

// compact returns the compact form of a valid JSON value. Numbers and
// strings keep their text.
func compact(v jsontext.Value) (jsontext.Value, error) {
	c := v.Clone()
	if err := c.Compact(); err != nil {
		return nil, err
	}
	return c, nil
}

func marshalValue(v any) jsontext.Value {
	b, err := json.Marshal(v)
	if err != nil {
		// Only strings, booleans and integers are marshalled here.
		panic(err)
	}
	return b
}
