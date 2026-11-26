package qrcode

// alignmentPositions lists the centre coordinates of the alignment patterns
// per version (ISO/IEC 18004 annex E).
var alignmentPositions = [40][]int{
	{}, {6, 18}, {6, 22}, {6, 26}, {6, 30}, {6, 34}, {6, 22, 38}, {6, 24, 42},
	{6, 26, 46}, {6, 28, 50}, {6, 30, 54}, {6, 32, 58}, {6, 34, 62},
	{6, 26, 46, 66}, {6, 26, 48, 70}, {6, 26, 50, 74}, {6, 30, 54, 78},
	{6, 30, 56, 82}, {6, 30, 58, 86}, {6, 34, 62, 90}, {6, 28, 50, 72, 94},
	{6, 26, 50, 74, 98}, {6, 30, 54, 78, 102}, {6, 28, 54, 80, 106},
	{6, 32, 58, 84, 110}, {6, 30, 58, 86, 114}, {6, 34, 62, 90, 118},
	{6, 26, 50, 74, 98, 122}, {6, 30, 54, 78, 102, 126}, {6, 26, 52, 78, 104, 130},
	{6, 30, 56, 82, 108, 134}, {6, 34, 60, 86, 112, 138}, {6, 30, 58, 86, 114, 142},
	{6, 34, 62, 90, 118, 146}, {6, 30, 54, 78, 102, 126, 150}, {6, 24, 50, 76, 102, 128, 154},
	{6, 28, 54, 80, 106, 132, 158}, {6, 32, 58, 84, 110, 136, 162}, {6, 26, 54, 82, 110, 138, 166},
	{6, 30, 58, 86, 114, 142, 170},
}

// matrix is a symbol under construction. fixed marks function modules and
// modules already written; the data goes into the others.
type matrix struct {
	version int
	size    int
	dark    []bool
	fixed   []bool
}

func newMatrix(version int) *matrix {
	size := 17 + 4*version
	m := &matrix{version: version, size: size, dark: make([]bool, size*size), fixed: make([]bool, size*size)}
	m.finder(0, 0)
	m.finder(size-7, 0)
	m.finder(0, size-7)
	m.alignment()
	m.timing()
	return m
}

func (m *matrix) clone() *matrix {
	c := *m
	c.dark = append([]bool(nil), m.dark...)
	c.fixed = append([]bool(nil), m.fixed...)
	return &c
}

func (m *matrix) set(row, col int, dark bool) {
	m.dark[row*m.size+col] = dark
	m.fixed[row*m.size+col] = true
}

func (m *matrix) isFixed(row, col int) bool { return m.fixed[row*m.size+col] }

// finder draws a finder pattern with its separator at row, col.
func (m *matrix) finder(row, col int) {
	for r := -1; r <= 7; r++ {
		if row+r < 0 || row+r >= m.size {
			continue
		}
		for c := -1; c <= 7; c++ {
			if col+c < 0 || col+c >= m.size {
				continue
			}
			dark := (r >= 0 && r <= 6 && (c == 0 || c == 6)) ||
				(c >= 0 && c <= 6 && (r == 0 || r == 6)) ||
				(r >= 2 && r <= 4 && c >= 2 && c <= 4)
			m.set(row+r, col+c, dark)
		}
	}
}

// alignment draws the alignment patterns whose centre is still free.
func (m *matrix) alignment() {
	pos := alignmentPositions[m.version-1]
	for _, row := range pos {
		for _, col := range pos {
			if m.isFixed(row, col) {
				continue
			}
			for r := -2; r <= 2; r++ {
				for c := -2; c <= 2; c++ {
					m.set(row+r, col+c, r == -2 || r == 2 || c == -2 || c == 2 || (r == 0 && c == 0))
				}
			}
		}
	}
}

func (m *matrix) timing() {
	for i := 8; i < m.size-8; i++ {
		if !m.isFixed(i, 6) {
			m.set(i, 6, i%2 == 0)
		}
		if !m.isFixed(6, i) {
			m.set(6, i, i%2 == 0)
		}
	}
}

// place writes format and version information, the dark module and the
// masked data. In a trial (scoring a mask) the information modules and the
// dark module are written light, as the Python library does.
func (m *matrix) place(level Level, mask int, codewords []byte, trial bool) {
	m.formatInfo(level, mask, trial)
	if m.version >= 7 {
		m.versionInfo(trial)
	}
	m.data(codewords, mask)
}

func (m *matrix) formatInfo(level Level, mask int, trial bool) {
	bits := bchFormat(level.formatBits()<<3 | mask)
	for i := range 15 {
		dark := !trial && (bits>>i)&1 == 1
		switch {
		case i < 6:
			m.set(i, 8, dark)
		case i < 8:
			m.set(i+1, 8, dark)
		default:
			m.set(m.size-15+i, 8, dark)
		}
		switch {
		case i < 8:
			m.set(8, m.size-i-1, dark)
		case i < 9:
			m.set(8, 15-i, dark)
		default:
			m.set(8, 14-i, dark)
		}
	}
	m.set(m.size-8, 8, !trial)
}

func (m *matrix) versionInfo(trial bool) {
	bits := bchVersion(m.version)
	for i := range 18 {
		dark := !trial && (bits>>i)&1 == 1
		m.set(i/3, i%3+m.size-11, dark)
		m.set(i%3+m.size-11, i/3, dark)
	}
}

// data fills the free modules in the zigzag order, two columns at a time
// from the bottom right, skipping the vertical timing column.
func (m *matrix) data(codewords []byte, mask int) {
	inc, row, bit, index := -1, m.size-1, 7, 0
	for right := m.size - 1; right > 0; right -= 2 {
		col := right
		if col <= 6 {
			col--
		}
		for {
			for _, c := range [2]int{col, col - 1} {
				if m.isFixed(row, c) {
					continue
				}
				dark := index < len(codewords) && (codewords[index]>>bit)&1 == 1
				if masked(mask, row, c) {
					dark = !dark
				}
				m.set(row, c, dark)
				bit--
				if bit < 0 {
					index++
					bit = 7
				}
			}
			row += inc
			if row < 0 || row >= m.size {
				row -= inc
				inc = -inc
				break
			}
		}
	}
}

func masked(mask, i, j int) bool {
	switch mask {
	case 0:
		return (i+j)%2 == 0
	case 1:
		return i%2 == 0
	case 2:
		return j%3 == 0
	case 3:
		return (i+j)%3 == 0
	case 4:
		return (i/2+j/3)%2 == 0
	case 5:
		return (i*j)%2+(i*j)%3 == 0
	case 6:
		return ((i*j)%2+(i*j)%3)%2 == 0
	default:
		return ((i*j)%3+(i+j)%2)%2 == 0
	}
}

func bchDigit(v int) int {
	n := 0
	for ; v != 0; v >>= 1 {
		n++
	}
	return n
}

func bchFormat(data int) int {
	const g15, mask15 = 0b10100110111, 0b101010000010010
	d := data << 10
	for bchDigit(d)-bchDigit(g15) >= 0 {
		d ^= g15 << (bchDigit(d) - bchDigit(g15))
	}
	return (data<<10 | d) ^ mask15
}

func bchVersion(version int) int {
	const g18 = 0b1111100100101
	d := version << 12
	for bchDigit(d)-bchDigit(g18) >= 0 {
		d ^= g18 << (bchDigit(d) - bchDigit(g18))
	}
	return version<<12 | d
}
