package qrcode

// Segment modes and their mode indicators.
const (
	modeNumeric  = 1
	modeAlnum    = 2
	modeByte     = 4
	minSplitRun  = 20 // the "optimize" default of the Python library
	alnumCharset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
)

type segment struct {
	mode int
	data []byte
}

// bits returns the length of the encoded data without header.
func (s segment) bits() int {
	n := len(s.data)
	switch s.mode {
	case modeNumeric:
		return 10*(n/3) + [...]int{0, 4, 7}[n%3]
	case modeAlnum:
		return 11*(n/2) + 6*(n%2)
	default:
		return 8 * n
	}
}

func (s segment) write(b *bitBuffer) {
	switch s.mode {
	case modeNumeric:
		for i := 0; i < len(s.data); i += 3 {
			chunk := s.data[i:min(i+3, len(s.data))]
			v := 0
			for _, c := range chunk {
				v = 10*v + int(c-'0')
			}
			b.put(v, [...]int{0, 4, 7, 10}[len(chunk)])
		}
	case modeAlnum:
		for i := 0; i < len(s.data); i += 2 {
			if i+1 < len(s.data) {
				b.put(alnumIndex(s.data[i])*45+alnumIndex(s.data[i+1]), 11)
			} else {
				b.put(alnumIndex(s.data[i]), 6)
			}
		}
	default:
		for _, c := range s.data {
			b.put(int(c), 8)
		}
	}
}

func alnumIndex(c byte) int {
	for i := range len(alnumCharset) {
		if alnumCharset[i] == c {
			return i
		}
	}
	return -1
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isAlnum(c byte) bool { return alnumIndex(c) >= 0 }

// lengthBits returns the size of the character count field.
func lengthBits(mode, version int) int {
	class := versionClass(version)
	switch mode {
	case modeNumeric:
		return [...]int{10, 12, 14}[class]
	case modeAlnum:
		return [...]int{9, 11, 13}[class]
	default:
		return [...]int{8, 16, 16}[class]
	}
}

// segments splits data like optimal_data_chunks(data, minimum=20) of the
// Python library: first numeric runs, then alphanumeric runs in what is
// left, everything else in byte mode. Data of at most 20 bytes becomes one
// segment of the densest mode that covers all of it.
func segments(data []byte) []segment {
	var out []segment
	for _, part := range split(data, isDigit) {
		if part.match {
			out = append(out, segment{modeNumeric, part.data})
			continue
		}
		for _, sub := range splitWith(part.data, isAlnum, len(data)) {
			mode := modeByte
			if sub.match {
				mode = modeAlnum
			}
			out = append(out, segment{mode, sub.data})
		}
	}
	return out
}

type piece struct {
	match bool
	data  []byte
}

func split(data []byte, class func(byte) bool) []piece {
	return splitWith(data, class, len(data))
}

// splitWith mirrors _optimal_split with the pattern compiled for a whole
// input of length total: a full match of the class for total <= 20,
// otherwise the leftmost run of at least 20 class characters.
func splitWith(data []byte, class func(byte) bool, total int) []piece {
	var out []piece
	if total <= minSplitRun {
		if len(data) == 0 {
			return nil
		}
		all := true
		for _, c := range data {
			all = all && class(c)
		}
		return []piece{{all, data}}
	}
	for len(data) > 0 {
		start, end := longRun(data, class)
		if start < 0 {
			break
		}
		if start > 0 {
			out = append(out, piece{false, data[:start]})
		}
		out = append(out, piece{true, data[start:end]})
		data = data[end:]
	}
	if len(data) > 0 {
		out = append(out, piece{false, data})
	}
	return out
}

// longRun returns the first maximal run of class characters with at least
// minSplitRun bytes, or -1.
func longRun(data []byte, class func(byte) bool) (start, end int) {
	for i := 0; i < len(data); {
		if !class(data[i]) {
			i++
			continue
		}
		j := i
		for j < len(data) && class(data[j]) {
			j++
		}
		if j-i >= minSplitRun {
			return i, j
		}
		i = j
	}
	return -1, -1
}

type bitBuffer struct {
	bytes []byte
	n     int
}

func (b *bitBuffer) put(v, length int) {
	for i := length - 1; i >= 0; i-- {
		b.putBit((v>>i)&1 == 1)
	}
}

func (b *bitBuffer) putBit(bit bool) {
	if b.n%8 == 0 {
		b.bytes = append(b.bytes, 0)
	}
	if bit {
		b.bytes[b.n/8] |= 0x80 >> (b.n % 8)
	}
	b.n++
}

// encodeData returns the final codeword sequence: data with terminator and
// padding, split into blocks, interleaved with their error correction.
func encodeData(segs []segment, version int, level Level) []byte {
	var b bitBuffer
	for _, s := range segs {
		b.put(s.mode, 4)
		b.put(len(s.data), lengthBits(s.mode, version))
		s.write(&b)
	}
	limit := dataBits(version, level)
	for range min(limit-b.n, 4) {
		b.putBit(false)
	}
	for b.n%8 != 0 {
		b.putBit(false)
	}
	for i := 0; b.n < limit; i++ {
		b.put([...]int{0xEC, 0x11}[i%2], 8)
	}
	return interleave(b.bytes, blocks(version, level))
}
