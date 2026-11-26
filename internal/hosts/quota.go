package hosts

import (
	"context"
	"encoding/json/jsontext"
	"fmt"
	"unicode/utf8"

	"github.com/bifrost0x/webssh/internal/store"
)

// The byte limits of saved connection data are those of
// app/connection_storage_policy.py, which measured the JSON files. Each
// store is measured as Python would write it, json.dumps(document,
// indent=2) with ASCII escapes, or in its compact form when only that one
// fits; the three stores of a user count together. Like Python, a write is
// refused only if it grows a store beyond a limit.

// Store documents and their schema versions (CURRENT_STORAGE_VERSIONS).
type kind struct {
	table   table
	key     string
	version int64
}

var (
	profileKind = kind{profileTable, "profiles", 3}
	jumpKind    = kind{jumpTable, "jump_hosts", 2}
	socksKind   = kind{socksTable, "socks_proxies", 2}
	allKinds    = []kind{profileKind, jumpKind, socksKind}
)

func (k kind) maxRecords(l Limits) int {
	switch k.key {
	case "profiles":
		return l.ProfileMaxRecords
	case "jump_hosts":
		return l.JumpHostMaxRecords
	}
	return l.SOCKSProxyMaxRecords
}

// documentSize is the size of the store file Python writes for records.
func documentSize(k kind, records []record, indent bool) int {
	var items []int
	for _, r := range records {
		items = append(items, objectSize(r, 2, indent))
	}
	list := containerSize(items, 1, indent)
	version := len(fmt.Sprint(k.version))
	return containerSize([]int{
		stringSize("schema_version") + keySep(indent) + version,
		stringSize(k.key) + keySep(indent) + list,
	}, 0, indent)
}

func keySep(indent bool) int {
	if indent {
		return 2 // ": "
	}
	return 1
}

// containerSize is the size of an object or array whose items have the
// given sizes, at nesting depth depth.
func containerSize(items []int, depth int, indent bool) int {
	if len(items) == 0 {
		return 2
	}
	size := 2 + len(items) - 1 // brackets and commas
	for _, item := range items {
		size += item
		if indent {
			size += 1 + 2*(depth+1) // newline and indentation
		}
	}
	if indent {
		size += 1 + 2*depth
	}
	return size
}

func objectSize(r record, depth int, indent bool) int {
	items := make([]int, len(r.members))
	for i, m := range r.members {
		items[i] = stringSize(m.name) + keySep(indent) + valueSize(m.value, depth, indent)
	}
	return containerSize(items, depth, indent)
}

func valueSize(v jsontext.Value, depth int, indent bool) int {
	switch v.Kind() {
	case '"':
		s, _ := asString(v)
		return stringSize(s)
	case '{':
		r, err := parseRecord(v)
		if err != nil {
			return len(v)
		}
		return objectSize(r, depth+1, indent)
	case '[':
		var elems []jsontext.Value
		if err := unmarshalArray(v, &elems); err != nil {
			return len(v)
		}
		items := make([]int, len(elems))
		for i, e := range elems {
			items[i] = valueSize(e, depth+1, indent)
		}
		return containerSize(items, depth+1, indent)
	}
	// Numbers and literals as written; Python re-renders floats, which
	// may differ by a few bytes.
	return len(v)
}

// stringSize is the length of a string as json.dumps writes it with
// ensure_ascii.
func stringSize(s string) int {
	size := 2
	for _, r := range s {
		switch {
		case r == '"' || r == '\\' || r == '\n' || r == '\r' || r == '\t' || r == '\b' || r == '\f':
			size += 2
		case r < 0x20:
			size += 6
		case r < utf8.RuneSelf:
			size++
		case r > 0xffff:
			size += 12
		default:
			size += 6
		}
	}
	return size
}

// stores holds the three record lists of one user during a write.
type stores map[string][]record

func loadStores(ctx context.Context, tx *store.Tx, owner int64) (stores, error) {
	all := stores{}
	for _, k := range allKinds {
		records, err := load(ctx, tx, k.table, owner)
		if err != nil {
			return nil, err
		}
		all[k.key] = records
	}
	return all, nil
}

// checkGrowth is enforce_store_transition for an ordinary write that
// replaces the records of k with next.
func checkGrowth(l Limits, k kind, all stores, next []record) error {
	previous := all[k.key]
	if limit := k.maxRecords(l); len(next) > limit && len(next) > len(previous) {
		return quotaError(fmt.Sprintf("more than %d records are not allowed", limit))
	}
	current := documentSize(k, previous, true)
	others := 0
	for _, other := range allKinds {
		if other.key != k.key {
			others += documentSize(other, all[other.key], true)
		}
	}
	var last error
	for _, indent := range []bool{true, false} {
		size := documentSize(k, next, indent)
		switch {
		case size > l.StoreMaxBytes && size > current:
			last = quotaError("one connection store would exceed its byte limit")
		case size+others > l.ConfigMaxBytes && size > current:
			last = quotaError("combined connection data would exceed its byte limit")
		default:
			return nil
		}
	}
	return last
}
