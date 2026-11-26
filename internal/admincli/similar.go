package admincli

import (
	"cmp"
	"slices"
)

// closeMatches is Python's difflib.get_close_matches(word, possibilities)
// with its defaults (at most 3 results, cutoff 0.6), which Click uses to
// suggest an option for a mistyped one. Results are ordered by score, best
// first, and among equal scores by the larger string, as heapq.nlargest
// orders the (score, string) pairs.
func closeMatches(word string, possibilities []string) []string {
	type scored struct {
		score float64
		s     string
	}
	var hits []scored
	for _, p := range possibilities {
		if r := ratio(p, word); r >= 0.6 {
			hits = append(hits, scored{r, p})
		}
	}
	slices.SortStableFunc(hits, func(a, b scored) int {
		if c := cmp.Compare(b.score, a.score); c != 0 {
			return c
		}
		return cmp.Compare(b.s, a.s)
	})
	out := make([]string, 0, 3)
	for i := 0; i < len(hits) && i < 3; i++ {
		out = append(out, hits[i].s)
	}
	return out
}

// ratio is difflib.SequenceMatcher(None, a, b).ratio() for short strings
// without junk: 2*M/T, where M counts the characters of the matching
// blocks and T is the total length.
func ratio(a, b string) float64 {
	ra, rb := []rune(a), []rune(b)
	total := len(ra) + len(rb)
	if total == 0 {
		return 1
	}
	return 2 * float64(matching(ra, rb, 0, len(ra), 0, len(rb))) / float64(total)
}

// matching sums the sizes of the matching blocks of a[alo:ahi] and
// b[blo:bhi], recursing on both sides of the longest match like
// get_matching_blocks.
func matching(a, b []rune, alo, ahi, blo, bhi int) int {
	i, j, k := longestMatch(a, b, alo, ahi, blo, bhi)
	if k == 0 {
		return 0
	}
	n := k
	if alo < i && blo < j {
		n += matching(a, b, alo, i, blo, j)
	}
	if i+k < ahi && j+k < bhi {
		n += matching(a, b, i+k, ahi, j+k, bhi)
	}
	return n
}

// longestMatch is find_longest_match without junk: the longest common
// block, the one that starts earliest in a among equals, then earliest in
// b.
func longestMatch(a, b []rune, alo, ahi, blo, bhi int) (besti, bestj, bestk int) {
	besti, bestj = alo, blo
	prev := map[int]int{}
	for i := alo; i < ahi; i++ {
		next := map[int]int{}
		for j := blo; j < bhi; j++ {
			if b[j] != a[i] {
				continue
			}
			k := prev[j-1] + 1
			next[j] = k
			if k > bestk {
				besti, bestj, bestk = i-k+1, j-k+1, k
			}
		}
		prev = next
	}
	return besti, bestj, bestk
}
