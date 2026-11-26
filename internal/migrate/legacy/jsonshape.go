package legacy

import (
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"maps"
	"slices"
	"strings"
)

var errShape = errors.New("malformed structure")

// exactObject decodes an object whose member names must be exactly keys,
// as Python's "set(document) == {...}" checks do.
func exactObject(raw []byte, keys ...string) (map[string]jsontext.Value, error) {
	var m map[string]jsontext.Value
	if err := json.Unmarshal(raw, &m); err != nil || m == nil {
		return nil, errShape
	}
	if !slices.Equal(slices.Sorted(maps.Keys(m)), slices.Sorted(slices.Values(keys))) {
		return nil, errShape
	}
	return m, nil
}

// pyText mirrors app/automation_store.py text(): a string without NUL, not
// blank unless empty is allowed, at most maximum UTF-8 bytes.
func pyText(raw jsontext.Value, maximum int, empty bool) (string, bool) {
	var s string
	if json.Unmarshal(raw, &s) != nil || strings.ContainsRune(s, 0) || len(s) > maximum {
		return "", false
	}
	if !empty && strings.TrimSpace(s) == "" {
		return "", false
	}
	return s, true
}

// pyString decodes a JSON string of any content.
func pyString(raw jsontext.Value) (string, bool) {
	var s string
	return s, json.Unmarshal(raw, &s) == nil
}

func isLowerHex(s string, n int) bool {
	return len(s) == n && strings.Trim(s, "0123456789abcdef") == ""
}
