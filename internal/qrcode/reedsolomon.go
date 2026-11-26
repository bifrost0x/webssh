package qrcode

// GF(256) with the QR code polynomial x^8 + x^4 + x^3 + x^2 + 1.
var gfExp, gfLog = func() (exp [512]byte, log [256]int) {
	x := 1
	for i := range 255 {
		exp[i] = byte(x)
		log[x] = i
		x <<= 1
		if x&0x100 != 0 {
			x ^= 0x11d
		}
	}
	for i := 255; i < 512; i++ {
		exp[i] = exp[i-255]
	}
	return exp, log
}()

func gfMul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return gfExp[gfLog[a]+gfLog[b]]
}

// generator returns the coefficients of (x - α^0)…(x - α^(n-1)), highest
// degree first, without the leading 1.
func generator(n int) []byte {
	g := []byte{1}
	for i := range n {
		next := make([]byte, len(g)+1)
		for j, c := range g {
			next[j] ^= c
			next[j+1] ^= gfMul(c, gfExp[i])
		}
		g = next
	}
	return g[1:]
}

// remainder returns the n error correction codewords of data.
func remainder(data []byte, n int) []byte {
	g := generator(n)
	r := make([]byte, n)
	for _, d := range data {
		factor := d ^ r[0]
		copy(r, r[1:])
		r[n-1] = 0
		for i := range n {
			r[i] ^= gfMul(g[i], factor)
		}
	}
	return r
}

type block struct{ total, data int }

func blocks(version int, level Level) []block {
	var out []block
	groups := blockTable[version-1][level]
	for i := 0; i+2 < len(groups); i += 3 {
		for range groups[i] {
			out = append(out, block{groups[i+1], groups[i+2]})
		}
	}
	return out
}

// interleave splits data into the blocks, computes their error correction
// and interleaves first the data and then the error correction codewords.
func interleave(data []byte, bs []block) []byte {
	var dcs, ecs [][]byte
	maxDC, maxEC, offset := 0, 0, 0
	for _, b := range bs {
		dc := data[offset : offset+b.data]
		offset += b.data
		ec := remainder(dc, b.total-b.data)
		dcs, ecs = append(dcs, dc), append(ecs, ec)
		maxDC, maxEC = max(maxDC, len(dc)), max(maxEC, len(ec))
	}
	out := make([]byte, 0, offset+maxEC*len(bs))
	for i := range maxDC {
		for _, dc := range dcs {
			if i < len(dc) {
				out = append(out, dc[i])
			}
		}
	}
	for i := range maxEC {
		for _, ec := range ecs {
			if i < len(ec) {
				out = append(out, ec[i])
			}
		}
	}
	return out
}
