package settings

import (
	"encoding/json/jsontext"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ValidOverviewPanels reports whether v is a panel arrangement the
// browser may store: null for the default layout, or a list of distinct
// known panels with a width of 3 to 12 columns, an optional height of 8 to
// 160 rows (null follows the content) and an optional hidden flag.
func ValidOverviewPanels(v jsontext.Value) bool {
	if isNull(v) {
		return true
	}
	items, ok := asArray(v)
	if !ok || len(items) > len(OverviewPanels) {
		return false
	}
	seen := make(map[string]bool, len(items))
	for _, item := range items {
		id, ok := panelID(item)
		if !ok || seen[id] {
			return false
		}
		seen[id] = true
	}
	return true
}

// panelID validates one placement and returns its panel.
func panelID(item jsontext.Value) (string, bool) {
	members, ok := asObject(item)
	if !ok {
		return "", false
	}
	var id string
	hasID, hasWidth := false, false
	for _, m := range members {
		switch m.name {
		case "id":
			s, ok := asString(m.value)
			if !ok || !in(OverviewPanels, s) {
				return "", false
			}
			id, hasID = s, true
		case "w":
			n, ok := asInt(m.value)
			if !ok || n < panelMinWidth || n > panelMaxWidth {
				return "", false
			}
			hasWidth = true
		case "h":
			if isNull(m.value) {
				continue
			}
			n, ok := asInt(m.value)
			if !ok || n < panelMinHeight || n > panelMaxHeight {
				return "", false
			}
		case "hidden":
			if _, ok := asBool(m.value); !ok {
				return "", false
			}
		default:
			return "", false
		}
	}
	return id, hasID && hasWidth
}

// ValidOverviewDismissed reports whether v is a list of at most 100
// distinct acknowledged attention items "kind:fingerprint".
func ValidOverviewDismissed(v jsontext.Value) bool {
	items, ok := asArray(v)
	if !ok || len(items) > DismissedLimit {
		return false
	}
	seen := make(map[string]bool, len(items))
	for _, item := range items {
		s, ok := asString(item)
		if !ok || !validDismissedItem(s) || seen[s] {
			return false
		}
		seen[s] = true
	}
	return true
}

func validDismissedItem(s string) bool {
	if utf8.RuneCountInString(s) > dismissedItemLimit {
		return false
	}
	kind, fingerprint, ok := strings.Cut(s, ":")
	if !ok || !in(dismissedKinds, kind) || fingerprint == "" {
		return false
	}
	for _, r := range fingerprint {
		if !pyAlnum(r) && r != '-' && r != '_' && r != '.' {
			return false
		}
	}
	return true
}

// pyAlnum approximates Python's str.isalnum for one character: letters
// (categories L*) and numbers (N*). Python also counts a few characters
// with a numeric value outside N*; fingerprints are produced by the page
// from host data and never contain them.
func pyAlnum(r rune) bool { return unicode.IsLetter(r) || unicode.IsNumber(r) }

// knownPanels keeps the valid placements of a stored arrangement, the
// first of each panel, and returns nil for none. Entries a newer release
// wrote are dropped on read instead of making the settings unreadable.
func knownPanels(v jsontext.Value) []jsontext.Value {
	items, ok := asArray(v)
	if !ok {
		return nil
	}
	var kept []jsontext.Value
	seen := map[string]bool{}
	for _, item := range items {
		if id, ok := panelID(item); ok && !seen[id] {
			seen[id] = true
			kept = append(kept, item)
		}
	}
	return kept
}

// knownDismissed keeps the valid, distinct items of a stored list, at
// most the last 100.
func knownDismissed(v jsontext.Value) []string {
	items, ok := asArray(v)
	kept := []string{}
	if !ok {
		return kept
	}
	seen := map[string]bool{}
	for _, item := range items {
		s, ok := asString(item)
		if ok && !seen[s] && validDismissedItem(s) {
			seen[s] = true
			kept = append(kept, s)
		}
	}
	if len(kept) > DismissedLimit {
		kept = kept[len(kept)-DismissedLimit:]
	}
	return kept
}
