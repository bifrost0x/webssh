package settings

import (
	"encoding/json/jsontext"
	"unicode"
	"unicode/utf8"
)

// The overview shows the host cards in the order an account gave them: a
// flat list of saved host ids, kept beside the panel arrangement. Hosts the
// list does not name follow in the default order, ids of deleted hosts are
// ignored by the page and dropped with its next save.
const (
	// HostOrderLimit bounds the list; an account keeps 500 saved hosts
	// unless PROFILE_MAX_RECORDS raises the limit.
	HostOrderLimit = 1000
	// hostOrderIDLimit bounds one id; saved hosts get UUIDs.
	hostOrderIDLimit = 64
)

// ValidOverviewHostOrder reports whether v is a host order the browser may
// store: null for the default order, or a list of at most HostOrderLimit
// distinct host ids.
func ValidOverviewHostOrder(v jsontext.Value) bool {
	if isNull(v) {
		return true
	}
	items, ok := asArray(v)
	if !ok || len(items) > HostOrderLimit {
		return false
	}
	seen := make(map[string]bool, len(items))
	for _, item := range items {
		id, ok := asString(item)
		if !ok || !validHostOrderID(id) || seen[id] {
			return false
		}
		seen[id] = true
	}
	return true
}

func validHostOrderID(id string) bool {
	if id == "" || utf8.RuneCountInString(id) > hostOrderIDLimit {
		return false
	}
	for _, r := range id {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// knownHostOrder keeps the usable, distinct ids of a stored list, at most
// HostOrderLimit. Entries a later release wrote are dropped on read instead
// of making the settings unreadable.
func knownHostOrder(v jsontext.Value) []string {
	items, _ := asArray(v)
	kept := []string{}
	seen := map[string]bool{}
	for _, item := range items {
		id, ok := asString(item)
		if ok && validHostOrderID(id) && !seen[id] && len(kept) < HostOrderLimit {
			seen[id] = true
			kept = append(kept, id)
		}
	}
	return kept
}
