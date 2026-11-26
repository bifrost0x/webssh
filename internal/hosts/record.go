package hosts

import (
	"bytes"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"strconv"
)

// member is one name/value pair of a stored record. The value is canonical
// JSON (see canonical): strings with minimal escaping, numbers exactly as
// they were written.
type member struct {
	name  string
	value jsontext.Value
}

// record is a JSON object that keeps its member order, like the Python
// dict it replaces. Setting a present member keeps its position, a new one
// is appended, a deleted one disappears: the order that results from a
// sequence of changes is the order Python's dict would have.
type record struct {
	members []member
}

var errNotObject = errors.New("hosts: value is not a JSON object")

// parseRecord reads one JSON object. Duplicate names, invalid UTF-8 and
// trailing data are refused.
func parseRecord(v jsontext.Value) (record, error) {
	dec := jsontext.NewDecoder(bytes.NewReader(v))
	tok, err := dec.ReadToken()
	if err != nil {
		return record{}, fmt.Errorf("hosts: read record: %w", err)
	}
	if tok.Kind() != '{' {
		return record{}, errNotObject
	}
	var r record
	for dec.PeekKind() != '}' {
		tok, err := dec.ReadToken()
		if err != nil {
			return record{}, fmt.Errorf("hosts: read member name: %w", err)
		}
		name := tok.String()
		raw, err := dec.ReadValue()
		if err != nil {
			return record{}, fmt.Errorf("hosts: read member %q: %w", name, err)
		}
		value, err := canonical(raw)
		if err != nil {
			return record{}, err
		}
		r.members = append(r.members, member{name: name, value: value})
	}
	if _, err := dec.ReadToken(); err != nil {
		return record{}, fmt.Errorf("hosts: read record end: %w", err)
	}
	if _, err := dec.ReadToken(); err != io.EOF {
		return record{}, errors.New("hosts: trailing data after record")
	}
	return r, nil
}

// canonical rewrites v token by token: whitespace goes, strings get the
// minimal escaping of the encoder, numbers keep their exact text, so
// integers beyond 2^53 survive.
func canonical(v jsontext.Value) (jsontext.Value, error) {
	dec := jsontext.NewDecoder(bytes.NewReader(v))
	var out bytes.Buffer
	enc := jsontext.NewEncoder(&out)
	for {
		tok, err := dec.ReadToken()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("hosts: canonical value: %w", err)
		}
		if err := enc.WriteToken(tok); err != nil {
			return nil, fmt.Errorf("hosts: canonical value: %w", err)
		}
	}
	return jsontext.Value(bytes.TrimRight(out.Bytes(), "\n")), nil
}

func (r *record) index(name string) int {
	for i, m := range r.members {
		if m.name == name {
			return i
		}
	}
	return -1
}

// get returns the value of name and whether it is present.
func (r *record) get(name string) (jsontext.Value, bool) {
	if i := r.index(name); i >= 0 {
		return r.members[i].value, true
	}
	return nil, false
}

func (r *record) has(name string) bool { return r.index(name) >= 0 }

// set stores value under name, in place when present.
func (r *record) set(name string, value jsontext.Value) {
	if i := r.index(name); i >= 0 {
		r.members[i].value = value
		return
	}
	r.members = append(r.members, member{name: name, value: value})
}

func (r *record) del(name string) {
	if i := r.index(name); i >= 0 {
		r.members = append(r.members[:i], r.members[i+1:]...)
	}
}

func (r record) clone() record {
	return record{members: append([]member(nil), r.members...)}
}

// cloneRecords copies records deeply enough that changing a member of a
// copy never changes the original.
func cloneRecords(in []record) []record {
	out := make([]record, len(in))
	for i, r := range in {
		out[i] = r.clone()
	}
	return out
}

// unmarshalArray decodes a JSON array into its raw elements.
func unmarshalArray(v jsontext.Value, out *[]jsontext.Value) error {
	return json.Unmarshal(v, out)
}

// str returns the member as a string when it is one.
func (r *record) str(name string) (string, bool) {
	v, ok := r.get(name)
	if !ok {
		return "", false
	}
	return asString(v)
}

// text returns the member as a string, or "" when it is absent or not a
// string (Python: profile.get(name, ”) used as text).
func (r *record) text(name string) string {
	s, _ := r.str(name)
	return s
}

// encode returns the record as one JSON object in member order.
func (r record) encode() jsontext.Value {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, m := range r.members {
		if i > 0 {
			b.WriteByte(',')
		}
		b.Write(jsonString(m.name))
		b.WriteByte(':')
		b.Write(m.value)
	}
	b.WriteByte('}')
	return jsontext.Value(b.Bytes())
}

// Values in canonical form.

var (
	jsonNull  = jsontext.Value("null")
	jsonTrue  = jsontext.Value("true")
	jsonFalse = jsontext.Value("false")
)

func jsonString(s string) jsontext.Value {
	b, err := json.Marshal(s)
	if err != nil {
		// Marshal fails only for invalid UTF-8, which never reaches here:
		// every string comes from a strictly decoded payload or a constant.
		panic(fmt.Sprintf("hosts: encode string: %v", err))
	}
	return b
}

func jsonInt(n int64) jsontext.Value { return jsontext.Value(strconv.FormatInt(n, 10)) }

func asString(v jsontext.Value) (string, bool) {
	if v.Kind() != '"' {
		return "", false
	}
	var s string
	if err := json.Unmarshal(v, &s); err != nil {
		return "", false
	}
	return s, true
}

// asInt returns v as an int64 when it is a JSON integer (Python: type(v)
// is int). Booleans and numbers with a fraction or exponent are not.
func asInt(v jsontext.Value) (int64, bool) {
	if v.Kind() != '0' {
		return 0, false
	}
	n, err := strconv.ParseInt(string(v), 10, 64)
	return n, err == nil
}

func isBool(v jsontext.Value) bool { return v.Kind() == 't' || v.Kind() == 'f' }

func isNull(v jsontext.Value) bool { return v.Kind() == 'n' }
