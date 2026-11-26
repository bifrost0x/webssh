package qrcode

// penalty scores a masked symbol as lost_point of the Python library. The
// skips in the 2x2 and finder-like searches are part of that scoring and
// decide which mask wins, so they are kept exactly.
func penalty(dark []bool, n int) int {
	at := func(r, c int) bool { return dark[r*n+c] }
	return runs(at, n) + blocks2x2(at, n) + finderLike(at, n) + balance(dark, n)
}

// runs scores rows and columns with five or more equal modules in a row.
func runs(at func(r, c int) bool, n int) int {
	score := 0
	for _, transpose := range [2]bool{false, true} {
		for i := range n {
			get := func(j int) bool {
				if transpose {
					return at(j, i)
				}
				return at(i, j)
			}
			prev, length := get(0), 0
			for j := range n {
				if get(j) == prev {
					length++
					continue
				}
				if length >= 5 {
					score += length - 2
				}
				length, prev = 1, get(j)
			}
			if length >= 5 {
				score += length - 2
			}
		}
	}
	return score
}

// blocks2x2 scores 2x2 blocks of one colour; a differing right column skips
// the next position.
func blocks2x2(at func(r, c int) bool, n int) int {
	score := 0
	for r := range n - 1 {
		for c := 0; c < n-1; c++ {
			topRight := at(r, c+1)
			switch {
			case topRight != at(r+1, c+1):
				c++
			case topRight != at(r, c), topRight != at(r+1, c):
			default:
				score += 3
			}
		}
	}
	return score
}

// finderLike scores 1:1:3:1:1 patterns with four light modules on one side.
// After a position whose eleventh module is dark the next one is skipped.
func finderLike(at func(r, c int) bool, n int) int {
	score := 0
	for _, transpose := range [2]bool{false, true} {
		for i := range n {
			get := func(j int) bool {
				if transpose {
					return at(j, i)
				}
				return at(i, j)
			}
			for j := 0; j < n-10; j++ {
				core := !get(j+1) && get(j+4) && !get(j+5) && get(j+6) && !get(j+9)
				left := get(j) && get(j+2) && get(j+3) && !get(j+7) && !get(j+8) && !get(j+10)
				right := !get(j) && !get(j+2) && !get(j+3) && get(j+7) && get(j+8) && get(j+10)
				if core && (left || right) {
					score += 40
				}
				if get(j + 10) {
					j++
				}
			}
		}
	}
	return score
}

// balance scores the share of dark modules in steps of five percent.
func balance(dark []bool, n int) int {
	count := 0
	for _, d := range dark {
		if d {
			count++
		}
	}
	percent := float64(count) / float64(n*n)
	diff := percent*100 - 50
	if diff < 0 {
		diff = -diff
	}
	return int(diff/5) * 10
}
