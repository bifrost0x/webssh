package idna2003

import (
	"slices"
	"sort"
	"sync"
)

// Hangul constants of the Unicode standard, section 3.12.
const (
	sBase  = 0xAC00
	lBase  = 0x1100
	vBase  = 0x1161
	tBase  = 0x11A7
	lCount = 19
	vCount = 21
	tCount = 28
	nCount = vCount * tCount
	sCount = lCount * nCount
)

func combiningClass(r rune) uint8 {
	t := combiningClasses
	i := sort.Search(len(t), func(i int) bool { return t[i].hi >= r })
	if i < len(t) && t[i].lo <= r {
		return t[i].class
	}
	return 0
}

// composer holds the composition pairs by first character.
type composer struct {
	pairs map[[2]rune]rune
	first map[rune]bool
}

var composeTable = sync.OnceValue(func() composer {
	c := composer{pairs: make(map[[2]rune]rune, len(compositions)), first: map[rune]bool{}}
	for _, p := range compositions {
		c.pairs[[2]rune{p.first, p.second}] = p.composed
		c.first[p.first] = true
	}
	return c
})

// nfkc is unicodedata.ucd_3_2_0.normalize("NFKC", s) of CPython, which
// decomposes with the data of Unicode 3.2.0 but orders and composes with
// the combining classes and pairs of its current Unicode version. The
// composition loop follows nfc_nfkc in Modules/unicodedata.c.
func nfkc(s []rune) []rune {
	if len(s) == 0 {
		return s
	}
	d := nfkd(s)
	c := composeTable()
	out := make([]rune, 0, len(d))
	skipped := make([]bool, len(d))
	for i := 0; i < len(d); {
		if skipped[i] {
			i++
			continue
		}
		code := d[i]
		if code >= lBase && code < lBase+lCount && i+1 < len(d) && d[i+1] >= vBase && d[i+1] < vBase+vCount {
			code = sBase + ((code-lBase)*vCount+(d[i+1]-vBase))*tCount
			i += 2
			if i < len(d) && d[i] > tBase && d[i] < tBase+tCount {
				code += d[i] - tBase
				i++
			}
			out = append(out, code)
			continue
		}
		if !c.first[code] {
			out = append(out, code)
			i++
			continue
		}
		// Only starters begin a pair, and a scan stops at the first
		// starter it cannot compose with, so no earlier scan has
		// consumed a position this one reaches.
		var comb uint8
		for i1 := i + 1; i1 < len(d); i1++ {
			code1 := d[i1]
			comb1 := combiningClass(code1)
			if comb != 0 {
				if comb1 == 0 {
					break
				}
				if comb >= comb1 {
					continue
				}
			}
			composed, ok := c.pairs[[2]rune{code, code1}]
			if !ok {
				if comb1 == 0 {
					break
				}
				comb = comb1
				continue
			}
			code = composed
			skipped[i1] = true
			if !c.first[code] {
				break
			}
		}
		out = append(out, code)
		i++
	}
	return out
}

// nfkd decomposes fully and orders each run of combining characters by
// class, keeping the order of equal classes.
func nfkd(s []rune) []rune {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		if r >= sBase && r < sBase+sCount {
			si := r - sBase
			out = append(out, lBase+si/nCount, vBase+(si%nCount)/tCount)
			if t := tBase + si%tCount; t != tBase {
				out = append(out, t)
			}
			continue
		}
		if to, ok := lookup(decompositions, r); ok {
			out = append(out, []rune(to)...)
			continue
		}
		out = append(out, r)
	}
	for i := 0; i < len(out); {
		if combiningClass(out[i]) == 0 {
			i++
			continue
		}
		start := i
		for i < len(out) && combiningClass(out[i]) != 0 {
			i++
		}
		slices.SortStableFunc(out[start:i], func(a, b rune) int {
			return int(combiningClass(a)) - int(combiningClass(b))
		})
	}
	return out
}
