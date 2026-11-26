package idna2003

import (
	"slices"
	"sort"
)

// span is an inclusive range of code points.
type span struct{ lo, hi rune }

// mapping replaces one code point with a string.
type mapping struct {
	r  rune
	to string
}

// classSpan gives a range of code points one combining class.
type classSpan struct {
	lo, hi rune
	class  uint8
}

// composition is a canonical pair and the character it composes to.
type composition struct{ first, second, composed rune }

func inSpans(table []span, r rune) bool {
	i := sort.Search(len(table), func(i int) bool { return table[i].hi >= r })
	return i < len(table) && table[i].lo <= r
}

func lookup(table []mapping, r rune) (string, bool) {
	i, found := slices.BinarySearchFunc(table, r, func(m mapping, r rune) int { return int(m.r - r) })
	if !found {
		return "", false
	}
	return table[i].to, true
}

// nameprep is encodings.idna.nameprep: map (B.1 and B.2), NFKC, prohibit,
// check bidi. Unassigned code points are allowed (table A.1 is not
// checked), as in the Python codec.
func nameprep(label []rune) ([]rune, error) {
	mapped := make([]rune, 0, len(label))
	for _, r := range label {
		if inSpans(mapToNothing, r) {
			continue
		}
		if to, ok := lookup(caseMap, r); ok {
			mapped = append(mapped, []rune(to)...)
			continue
		}
		mapped = append(mapped, r)
	}
	out := nfkc(mapped)
	for _, r := range out {
		if inSpans(prohibitedChars, r) {
			return nil, ErrInvalid
		}
	}
	if !slices.ContainsFunc(out, func(r rune) bool { return inSpans(randALCat, r) }) {
		return out, nil
	}
	// RFC 3454, section 6: with an R or AL character there is no L
	// character, and the first and the last character are R or AL.
	if slices.ContainsFunc(out, func(r rune) bool { return inSpans(lCat, r) }) {
		return nil, ErrInvalid
	}
	if !inSpans(randALCat, out[0]) || !inSpans(randALCat, out[len(out)-1]) {
		return nil, ErrInvalid
	}
	return out, nil
}
