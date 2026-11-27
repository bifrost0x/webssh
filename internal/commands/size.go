package commands

import (
	"encoding/json/jsontext"
	json "encoding/json/v2"

	"github.com/bifrost0x/webssh/internal/pyjson"
)

// The byte limits of app/command_storage_policy.py measure the store files
// as Python writes them: json.dumps(document, indent=2) with ASCII
// escapes. The commands store is a list, the sets store an object with
// schema_version and command_sets; both count together against the
// combined limit.

// dumpSize is the length of json.dumps(v, indent=2) at nesting depth.
func dumpSize(v jsontext.Value, depth int) int64 {
	switch v.Kind() {
	case '"':
		var s string
		if err := json.Unmarshal(v, &s); err != nil {
			return int64(len(v))
		}
		return int64(len(pyjson.Quote(s)))
	case '{':
		members, ok := pyjson.Members(v)
		if !ok {
			return int64(len(v))
		}
		items := make([]int64, len(members))
		for i, m := range members {
			items[i] = int64(len(pyjson.Quote(m.Name))) + 2 + dumpSize(m.Value, depth+1)
		}
		return containerSize(items, depth)
	case '[':
		elems, ok := pyjson.Items(v)
		if !ok {
			return int64(len(v))
		}
		items := make([]int64, len(elems))
		for i, e := range elems {
			items[i] = dumpSize(e, depth+1)
		}
		return containerSize(items, depth)
	}
	// Numbers and literals as written; Python re-renders floats, which
	// may differ by a few bytes.
	return int64(len(v))
}

// containerSize is the size of an indented container whose items have
// the given sizes.
func containerSize(items []int64, depth int) int64 {
	if len(items) == 0 {
		return 2
	}
	size := int64(2 + len(items) - 1)
	for _, item := range items {
		size += item + 1 + 2*int64(depth+1)
	}
	return size + 1 + 2*int64(depth)
}

// commandsDocSize is the size of commands.json for these records.
func commandsDocSize(records []jsontext.Value) int64 {
	return dumpSize(pyjson.Array(records), 0)
}

// setsDocSize is the size of command_sets.json for these records.
func setsDocSize(records []jsontext.Value) int64 {
	return dumpSize(setsDocument(records), 0)
}

// setsDocument is the stored form of command_sets.json.
func setsDocument(records []jsontext.Value) jsontext.Value {
	return pyjson.Object([]pyjson.Member{
		{Name: "schema_version", Value: jsontext.Value("2")},
		{Name: "command_sets", Value: pyjson.Array(records)},
	})
}
