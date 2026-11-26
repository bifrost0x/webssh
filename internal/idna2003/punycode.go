package idna2003

import (
	"slices"
	"strings"
)

// punycode is punycode_encode of encodings.punycode (RFC 3492) for a
// label of fewer than maxLabel code points; ToASCII bounds it.
func punycode(label []rune) string {
	var b strings.Builder
	var extended []rune
	for _, r := range label {
		if r < 0x80 {
			b.WriteRune(r)
		} else {
			extended = append(extended, r)
		}
	}
	baseLen := b.Len()
	slices.Sort(extended)
	extended = slices.Compact(extended)
	if baseLen > 0 {
		b.WriteByte('-')
	}
	bias := 72
	points := 0
	emit := func(delta int) {
		writeInteger(&b, delta, bias)
		bias = adapt(delta, points == 0, baseLen+points+1)
		points++
	}
	// insertion_unsort: deltas between the insertion positions of each
	// extended code point, in increasing order.
	oldChar, oldIndex := rune(0x80), -1
	for _, c := range extended {
		curLen := 0
		for _, r := range label {
			if r < c {
				curLen++
			}
		}
		delta := (curLen + 1) * int(c-oldChar)
		index := -1
		for _, r := range label {
			switch {
			case r == c:
				index++
				delta += index - oldIndex
				emit(delta - 1)
				oldIndex = index
				delta = 0
			case r < c:
				index++
			}
		}
		oldChar = c
	}
	return b.String()
}

const punyDigits = "abcdefghijklmnopqrstuvwxyz0123456789"

func threshold(j, bias int) int {
	return min(max(36*(j+1)-bias, 1), 26)
}

// writeInteger is generate_generalized_integer.
func writeInteger(b *strings.Builder, n, bias int) {
	for j := 0; ; j++ {
		t := threshold(j, bias)
		if n < t {
			b.WriteByte(punyDigits[n])
			return
		}
		b.WriteByte(punyDigits[t+(n-t)%(36-t)])
		n = (n - t) / (36 - t)
	}
}

func adapt(delta int, first bool, numChars int) int {
	if first {
		delta /= 700
	} else {
		delta /= 2
	}
	delta += delta / numChars
	divisions := 0
	for delta > 455 {
		delta /= 35
		divisions += 36
	}
	return divisions + 36*delta/(delta+38)
}
