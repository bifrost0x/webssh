package files

import "slices"

// lineBlock maps the old lines [i1, i2) to the new lines [j1, j2).
type lineBlock struct{ i1, i2, j1, j2 int }

// lineOpcodes returns the blocks of difflib.SequenceMatcher(None, a, b,
// autojunk=True).get_opcodes() without their tags: the editor maps line
// endings with the same alignment as the Python release, so a save of a
// file with mixed line endings writes the same bytes.
func lineOpcodes(a, b []string) []lineBlock {
	m := newMatcher(a, b)
	var out []lineBlock
	i, j := 0, 0
	for _, mb := range m.matchingBlocks() {
		if i < mb.i || j < mb.j {
			out = append(out, lineBlock{i, mb.i, j, mb.j})
		}
		i, j = mb.i+mb.size, mb.j+mb.size
		if mb.size > 0 {
			out = append(out, lineBlock{mb.i, i, mb.j, j})
		}
	}
	return out
}

type match struct{ i, j, size int }

type matcher struct {
	a, b []string
	b2j  map[string][]int
}

// newMatcher indexes b as SequenceMatcher.__chain_b does with autojunk:
// with 200 or more lines, a line that occurs more than len(b)/100+1 times
// is popular and never starts a match (it may extend one).
func newMatcher(a, b []string) *matcher {
	b2j := make(map[string][]int)
	for j, line := range b {
		b2j[line] = append(b2j[line], j)
	}
	if n := len(b); n >= 200 {
		limit := n/100 + 1
		for line, idx := range b2j {
			if len(idx) > limit {
				delete(b2j, line)
			}
		}
	}
	return &matcher{a: a, b: b, b2j: b2j}
}

// longest is find_longest_match without junk: the longest block of
// a[alo:ahi] equal to b[blo:bhi], earliest in a, then earliest in b.
func (m *matcher) longest(alo, ahi, blo, bhi int) match {
	best := match{alo, blo, 0}
	j2len := map[int]int{}
	for i := alo; i < ahi; i++ {
		next := map[int]int{}
		for _, j := range m.b2j[m.a[i]] {
			if j < blo {
				continue
			}
			if j >= bhi {
				break
			}
			k := j2len[j-1] + 1
			next[j] = k
			if k > best.size {
				best = match{i - k + 1, j - k + 1, k}
			}
		}
		j2len = next
	}
	for best.i > alo && best.j > blo && m.a[best.i-1] == m.b[best.j-1] {
		best = match{best.i - 1, best.j - 1, best.size + 1}
	}
	for best.i+best.size < ahi && best.j+best.size < bhi && m.a[best.i+best.size] == m.b[best.j+best.size] {
		best.size++
	}
	return best
}

// matchingBlocks is get_matching_blocks: the matches in order with
// adjacent ones joined, ending with the sentinel (len(a), len(b), 0).
func (m *matcher) matchingBlocks() []match {
	type span struct{ alo, ahi, blo, bhi int }
	queue := []span{{0, len(m.a), 0, len(m.b)}}
	var found []match
	for len(queue) > 0 {
		s := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		x := m.longest(s.alo, s.ahi, s.blo, s.bhi)
		if x.size == 0 {
			continue
		}
		found = append(found, x)
		if s.alo < x.i && s.blo < x.j {
			queue = append(queue, span{s.alo, x.i, s.blo, x.j})
		}
		if x.i+x.size < s.ahi && x.j+x.size < s.bhi {
			queue = append(queue, span{x.i + x.size, s.ahi, x.j + x.size, s.bhi})
		}
	}
	slices.SortFunc(found, func(p, q match) int {
		if p.i != q.i {
			return p.i - q.i
		}
		if p.j != q.j {
			return p.j - q.j
		}
		return p.size - q.size
	})
	var out []match
	cur := match{}
	for _, x := range found {
		if cur.i+cur.size == x.i && cur.j+cur.size == x.j {
			cur.size += x.size
			continue
		}
		if cur.size > 0 {
			out = append(out, cur)
		}
		cur = x
	}
	if cur.size > 0 {
		out = append(out, cur)
	}
	return append(out, match{len(m.a), len(m.b), 0})
}
