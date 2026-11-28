// Package naming is the comparison form of the names users give their
// saved records: hosts, jump hosts, SOCKS5 proxies, SSH keys and saved
// passwords. Two names are the same when their keys are equal; each
// capability checks it inside the transaction that stores the record.
package naming

import (
	"slices"
	"strings"
	"unicode"
)

// Key is name trimmed as Python's str.strip() trims and case-folded as
// the Python import compared names (str.casefold, approximated by simple
// case folding plus ß and ẞ to "ss").
func Key(name string) string {
	var b strings.Builder
	for _, r := range strings.TrimFunc(name, isSpace) {
		switch r {
		case 'ß', 'ẞ':
			b.WriteString("ss")
		default:
			b.WriteRune(unicode.ToLower(unicode.ToUpper(r)))
		}
	}
	return b.String()
}

// isSpace is str.isspace() for one code point.
func isSpace(r rune) bool {
	switch r {
	case 0x1c, 0x1d, 0x1e, 0x1f:
		return true
	}
	return unicode.IsSpace(r) || unicode.Is(unicode.Zs, r)
}

// Taken reports whether name is in use among names by a record other than
// the ones at the positions own (none for a new record). A record that
// keeps its own name is never refused, so duplicates stored before names
// were unique stay editable; only moving onto another record's name is.
func Taken(names []string, own []int, name string) bool {
	key := Key(name)
	for _, i := range own {
		if Key(names[i]) == key {
			return false
		}
	}
	for i, n := range names {
		if !slices.Contains(own, i) && Key(n) == key {
			return true
		}
	}
	return false
}
