package oracletest

import (
	"bytes"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"fmt"
	"maps"
	"slices"
)

// sameCases reports whether two recordings hold the same requests and
// answers, whatever their layout.
func sameCases(a, b map[string]entry) bool {
	return maps.EqualFunc(a, b, func(x, y entry) bool {
		return x.Request == y.Request && bytes.Equal(compact(x.Answer), compact(y.Answer))
	})
}

func compact(v jsontext.Value) jsontext.Value {
	c := slices.Clone(v)
	if c.Compact() != nil {
		return v
	}
	return c
}

// format writes the document with sorted keys and one case per member.
// An answer that is an array, or a large object, gets one compact element
// or member per line, so that a changed answer shows as a small diff.
func (d document) format() ([]byte, error) {
	var b bytes.Buffer
	header, err := json.Marshal(d.Oracle, json.Deterministic(true), jsontext.WithIndent("  "), jsontext.WithIndentPrefix("  "))
	if err != nil {
		return nil, err
	}
	b.WriteString("{\n  \"oracle\": ")
	b.Write(header)
	b.WriteString(",\n  \"cases\": {")
	for i, key := range slices.Sorted(maps.Keys(d.Cases)) {
		e := d.Cases[key]
		name, err := jsontext.AppendQuote(nil, key)
		if err != nil {
			return nil, err
		}
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, "\n    %s: {\n      \"request_sha256\": %q,\n      \"answer\": ", name, e.Request)
		if err := writeAnswer(&b, e.Answer); err != nil {
			return nil, err
		}
		b.WriteString("\n    }")
	}
	b.WriteString("\n  }\n}\n")
	return b.Bytes(), nil
}

// splitObjects is the size above which an object answer is written one
// member per line.
const splitObjects = 1024

func writeAnswer(b *bytes.Buffer, answer jsontext.Value) error {
	const indent = "\n        "
	switch {
	case answer.Kind() == '[':
		var items []jsontext.Value
		if err := json.Unmarshal(answer, &items); err != nil {
			return err
		}
		if len(items) == 0 {
			b.WriteString("[]")
			return nil
		}
		b.WriteString("[")
		for i, item := range items {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(indent)
			b.Write(item)
		}
		b.WriteString("\n      ]")
	case answer.Kind() == '{' && len(answer) > splitObjects:
		var members map[string]jsontext.Value
		if err := json.Unmarshal(answer, &members); err != nil {
			return err
		}
		b.WriteString("{")
		for i, name := range slices.Sorted(maps.Keys(members)) {
			quoted, err := jsontext.AppendQuote(nil, name)
			if err != nil {
				return err
			}
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(indent)
			b.Write(quoted)
			b.WriteByte(':')
			b.Write(members[name])
		}
		b.WriteString("\n      }")
	default:
		b.Write(answer)
	}
	return nil
}
