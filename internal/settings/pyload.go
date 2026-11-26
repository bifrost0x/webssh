package settings

import (
	"bytes"
	"encoding/json/jsontext"
	"errors"
	"unicode/utf8"
)

// errPythonLoad marks a text json.loads of the Python release would
// refuse too: not UTF-8, or not JSON.
var errPythonLoad = errors.New("settings: not a JSON text")

// pythonLoad reads a JSON text the way the Python release does and returns
// it compact, with unique names and valid UTF-8, so the strict helpers of
// this package apply. For duplicate names the last value wins at the
// position of the first, as in a Python dict. An escaped unpaired
// surrogate ("\ud800"), which Python writes with ensure_ascii and reads
// back, cannot be held by a Go string; like the legacy reader
// (internal/migrate/legacy) it becomes U+FFFD and lone reports it. Number
// texts are kept unchanged.
func pythonLoad(raw []byte) (v jsontext.Value, lone bool, err error) {
	if !utf8.Valid(raw) {
		return nil, false, errPythonLoad
	}
	strict := jsontext.Value(raw).IsValid(jsontext.AllowDuplicateNames(true))
	if !strict && !jsontext.Value(raw).IsValid(jsontext.AllowDuplicateNames(true), jsontext.AllowInvalidUTF8(true)) {
		return nil, false, errPythonLoad
	}
	dec := jsontext.NewDecoder(bytes.NewReader(raw), jsontext.AllowDuplicateNames(true), jsontext.AllowInvalidUTF8(true))
	out, err := readLenient(dec, 0)
	if err != nil {
		return nil, false, errPythonLoad
	}
	return out, !strict, nil
}

func readLenient(dec *jsontext.Decoder, depth int) (jsontext.Value, error) {
	if depth > maxPythonDepth {
		return nil, errPythonLoad
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
			v, err := readLenient(dec, depth+1)
			if err != nil {
				return nil, err
			}
			if _, seen := values[name]; !seen {
				names = append(names, name)
			}
			values[name] = v
		}
		if _, err := dec.ReadToken(); err != nil {
			return nil, err
		}
		out := []byte{'{'}
		for i, name := range names {
			if i > 0 {
				out = append(out, ',')
			}
			out = append(out, marshalValue(name)...)
			out = append(out, ':')
			out = append(out, values[name]...)
		}
		return append(out, '}'), nil
	case '[':
		if _, err := dec.ReadToken(); err != nil {
			return nil, err
		}
		var items []jsontext.Value
		for dec.PeekKind() != ']' {
			v, err := readLenient(dec, depth+1)
			if err != nil {
				return nil, err
			}
			items = append(items, v)
		}
		if _, err := dec.ReadToken(); err != nil {
			return nil, err
		}
		return joinArray(items), nil
	case '"':
		tok, err := dec.ReadToken()
		if err != nil {
			return nil, err
		}
		return marshalValue(tok.String()), nil
	default:
		v, err := dec.ReadValue()
		if err != nil {
			return nil, err
		}
		return v.Clone(), nil
	}
}
