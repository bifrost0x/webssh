// Package pyjson reads and writes JSON text the way the Python release
// does with its json module. Go's strict decoder refuses two things
// Python's json.loads accepts and the Python release therefore has on
// disk: a repeated member name (the last value wins) and an escaped
// unpaired UTF-16 surrogate such as "\ud800", which json.dumps writes
// with its default ensure_ascii and json.loads reads back. Load accepts
// both and returns a value the strict decoder accepts, and says what it
// had to normalise, so callers can report it.
package pyjson

import (
	"bytes"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// MaxDepth bounds the nesting Load accepts. Python's decoder stops at the
// interpreter's recursion limit; no store of the Python release nests
// deeper than a few levels.
const MaxDepth = 512

// ErrSyntax marks a text json.loads refuses too: not UTF-8, not JSON,
// trailing data, or nested deeper than MaxDepth.
var ErrSyntax = errors.New("pyjson: not a JSON text")

// Report says what Load normalised.
type Report struct {
	// LoneSurrogates: at least one string held an escaped unpaired
	// surrogate. A Go string cannot hold it; it became U+FFFD.
	LoneSurrogates bool
	// DuplicateNames: at least one object repeated a member name. As in a
	// Python dict, the last value is kept at the position of the first.
	DuplicateNames bool
}

// Load reads raw like json.loads and returns it as compact JSON with
// unique member names and valid UTF-8. Number texts are kept exactly as
// written, so integers beyond 2^53 survive; strings are re-encoded with
// the minimal escaping of encoding/json/jsontext.
func Load(raw []byte) (jsontext.Value, Report, error) {
	var rep Report
	if !utf8.Valid(raw) {
		return nil, rep, ErrSyntax
	}
	opts := []jsontext.Options{jsontext.AllowDuplicateNames(true), jsontext.AllowInvalidUTF8(true)}
	if !jsontext.Value(raw).IsValid(opts...) {
		return nil, rep, ErrSyntax
	}
	rep.LoneSurrogates = !jsontext.Value(raw).IsValid(jsontext.AllowDuplicateNames(true))
	dec := jsontext.NewDecoder(bytes.NewReader(raw), opts...)
	out, err := read(dec, 0, &rep)
	if err != nil {
		return nil, Report{}, fmt.Errorf("%w: %v", ErrSyntax, err)
	}
	return out, rep, nil
}

func read(dec *jsontext.Decoder, depth int, rep *Report) (jsontext.Value, error) {
	if depth > MaxDepth {
		return nil, errors.New("nested too deeply")
	}
	switch dec.PeekKind() {
	case '{':
		if _, err := dec.ReadToken(); err != nil {
			return nil, err
		}
		var names []string
		values := map[string]jsontext.Value{}
		for dec.PeekKind() != '}' {
			tok, err := dec.ReadToken()
			if err != nil {
				return nil, err
			}
			name := tok.String()
			v, err := read(dec, depth+1, rep)
			if err != nil {
				return nil, err
			}
			if _, seen := values[name]; seen {
				rep.DuplicateNames = true
			} else {
				names = append(names, name)
			}
			values[name] = v
		}
		if _, err := dec.ReadToken(); err != nil {
			return nil, err
		}
		members := make([]Member, len(names))
		for i, name := range names {
			members[i] = Member{Name: name, Value: values[name]}
		}
		return Object(members), nil
	case '[':
		if _, err := dec.ReadToken(); err != nil {
			return nil, err
		}
		var items []jsontext.Value
		for dec.PeekKind() != ']' {
			v, err := read(dec, depth+1, rep)
			if err != nil {
				return nil, err
			}
			items = append(items, v)
		}
		if _, err := dec.ReadToken(); err != nil {
			return nil, err
		}
		return Array(items), nil
	case '"':
		tok, err := dec.ReadToken()
		if err != nil {
			return nil, err
		}
		return String(tok.String()), nil
	default:
		v, err := dec.ReadValue()
		if err != nil {
			return nil, err
		}
		return v.Clone(), nil
	}
}

// Member is one name and value of an object, in document order.
type Member struct {
	Name  string
	Value jsontext.Value
}

// Members returns the members of an object value in order, or false
// when v is not an object. v must come from Load or the builders of this
// package (unique names, valid UTF-8). The values share v's memory and
// must not be modified in place; appending to one copies it.
func Members(v jsontext.Value) ([]Member, bool) {
	if v.Kind() != '{' {
		return nil, false
	}
	dec := jsontext.NewDecoder(bytes.NewBuffer(v))
	if _, err := dec.ReadToken(); err != nil {
		return nil, false
	}
	var out []Member
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
		out = append(out, Member{Name: name, Value: capped(val)})
	}
	return out, true
}

// Items returns the items of an array value, or false when v is not an
// array. Like the values of Members, the items share v's memory.
func Items(v jsontext.Value) ([]jsontext.Value, bool) {
	if v.Kind() != '[' {
		return nil, false
	}
	dec := jsontext.NewDecoder(bytes.NewBuffer(v))
	if _, err := dec.ReadToken(); err != nil {
		return nil, false
	}
	var out []jsontext.Value
	for dec.PeekKind() != ']' {
		val, err := dec.ReadValue()
		if err != nil {
			return nil, false
		}
		out = append(out, capped(val))
	}
	return out, true
}

// Len returns the number of items of an array or members of an object
// without copying them, and 0 for any other value.
func Len(v jsontext.Value) int {
	if k := v.Kind(); k != '[' && k != '{' {
		return 0
	}
	dec := jsontext.NewDecoder(bytes.NewBuffer(v))
	if _, err := dec.ReadToken(); err != nil {
		return 0
	}
	n := 0
	for k := dec.PeekKind(); k != ']' && k != '}'; k = dec.PeekKind() {
		if v.Kind() == '{' {
			if _, err := dec.ReadToken(); err != nil {
				return n
			}
		}
		if err := dec.SkipValue(); err != nil {
			return n
		}
		n++
	}
	return n
}

// Get returns the value of the member name of an object. Other members
// are skipped without being copied, so a lookup in a large store does
// not allocate its size. The value shares v's memory.
func Get(v jsontext.Value, name string) (jsontext.Value, bool) {
	if v.Kind() != '{' {
		return nil, false
	}
	dec := jsontext.NewDecoder(bytes.NewBuffer(v))
	if _, err := dec.ReadToken(); err != nil {
		return nil, false
	}
	for dec.PeekKind() != '}' {
		tok, err := dec.ReadToken()
		if err != nil {
			return nil, false
		}
		if tok.String() != name {
			if err := dec.SkipValue(); err != nil {
				return nil, false
			}
			continue
		}
		val, err := dec.ReadValue()
		if err != nil {
			return nil, false
		}
		return capped(val), true
	}
	return nil, false
}

// capped limits the capacity of a value that aliases its document, so
// that an append copies instead of overwriting the bytes that follow.
// A decoder reading from a bytes.Buffer returns values inside that
// buffer and never writes to it.
func capped(v jsontext.Value) jsontext.Value { return v[:len(v):len(v)] }

// Set assigns name like a Python dict: an existing member keeps its
// position, a new one is appended.
func Set(members []Member, name string, value jsontext.Value) []Member {
	for i := range members {
		if members[i].Name == name {
			members[i].Value = value
			return members
		}
	}
	return append(members, Member{Name: name, Value: value})
}

// Delete removes name like dict.pop(name, None).
func Delete(members []Member, name string) []Member {
	for i := range members {
		if members[i].Name == name {
			return append(members[:i:i], members[i+1:]...)
		}
	}
	return members
}

// Object encodes members as a compact JSON object in their order.
func Object(members []Member) jsontext.Value {
	out := []byte{'{'}
	for i, m := range members {
		if i > 0 {
			out = append(out, ',')
		}
		out = append(out, String(m.Name)...)
		out = append(out, ':')
		out = append(out, m.Value...)
	}
	return append(out, '}')
}

// Array encodes items as a compact JSON array.
func Array(items []jsontext.Value) jsontext.Value {
	out := []byte{'['}
	for i, item := range items {
		if i > 0 {
			out = append(out, ',')
		}
		out = append(out, item...)
	}
	return append(out, ']')
}

// String encodes s with the minimal escaping of encoding/json/jsontext.
// s must be valid UTF-8; invalid bytes become U+FFFD.
func String(s string) jsontext.Value {
	out, _ := jsontext.AppendQuote(nil, s) // the error only reports the U+FFFD replacement
	return out
}

// Quote encodes s as Python's json.dumps does with ensure_ascii=True:
// every character outside printable ASCII as a \uXXXX escape, astral
// characters as a surrogate pair. Secrets of the Python release are bound
// to such text (AES-GCM additional data), so the bytes must match.
func Quote(s string) string {
	var b strings.Builder
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
		default:
			switch {
			case r < 0x20 || (r >= 0x7f && r <= 0xffff):
				writeEscape(&b, r)
			case r > 0xffff:
				hi, lo := utf16.EncodeRune(r)
				writeEscape(&b, hi)
				writeEscape(&b, lo)
			default:
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

const hexDigits = "0123456789abcdef"

func writeEscape(b *strings.Builder, r rune) {
	b.WriteString(`\u`)
	for shift := 12; shift >= 0; shift -= 4 {
		b.WriteByte(hexDigits[(r>>shift)&0xf])
	}
}
