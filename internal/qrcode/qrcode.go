// Package qrcode encodes QR codes (ISO/IEC 18004, model 2) for the TOTP
// enrolment page.
//
// The output is module for module the one of the Python release, which uses
// the qrcode library 8.x with its defaults: the data is split into numeric,
// alphanumeric and byte segments wherever a run of at least 20 characters
// fits a denser mode, the smallest version that holds the data is chosen,
// and the mask is the one with the lowest penalty as that library scores it.
// The library's penalty differs from the standard in small ways (it scores
// the mask with blank format and version areas, and its pattern search skips
// some positions); this package reproduces it, so a secret shows the same
// code before and after the switch. SVG renders the image the Python release
// sends.
//
// Kanji mode, structured append and ECI are not supported.
package qrcode

import (
	"errors"
	"sort"
)

// Level is an error correction level.
type Level int

// Error correction levels, from the least to the most redundant.
const (
	L Level = iota
	M
	Q
	H
)

// formatBits returns the two-bit level indicator of the format information.
func (l Level) formatBits() int {
	return [...]int{1, 0, 3, 2}[l]
}

func (l Level) valid() bool { return l >= L && l <= H }

// ErrTooLong reports data that does not fit into version 40 at the level.
var ErrTooLong = errors.New("qrcode: data does not fit into a QR code")

var errLevel = errors.New("qrcode: unknown error correction level")

// Code is an encoded QR code.
type Code struct {
	// Version is the symbol version, 1 to 40.
	Version int
	// Level is the error correction level.
	Level Level
	// Mask is the data mask pattern, 0 to 7.
	Mask int
	size int
	dark []bool
}

// Size returns the number of modules per side (17 + 4·Version).
func (c *Code) Size() int { return c.size }

// Dark reports whether the module in row and col is dark. Positions outside
// the symbol are light.
func (c *Code) Dark(row, col int) bool {
	if row < 0 || col < 0 || row >= c.size || col >= c.size {
		return false
	}
	return c.dark[row*c.size+col]
}

// Encode encodes data at level as the Python release does.
func Encode(data []byte, level Level) (*Code, error) {
	if !level.valid() {
		return nil, errLevel
	}
	segs := segments(data)
	version, err := fitVersion(segs, level)
	if err != nil {
		return nil, err
	}
	codewords := encodeData(segs, version, level)
	m := newMatrix(version)
	best, bestScore := 0, 0
	for mask := range 8 {
		trial := m.clone()
		trial.place(level, mask, codewords, true)
		score := penalty(trial.dark, trial.size)
		if mask == 0 || score < bestScore {
			best, bestScore = mask, score
		}
	}
	m.place(level, best, codewords, false)
	return &Code{Version: version, Level: level, Mask: best, size: m.size, dark: m.dark}, nil
}

// dataBits returns the number of data bits of version at level.
func dataBits(version int, level Level) int {
	n := 0
	for _, b := range blocks(version, level) {
		n += b.data
	}
	return 8 * n
}

// fitVersion returns the smallest version that holds segs, choosing the
// length field sizes of the version class the way the Python library does:
// it measures with the class of the starting version and starts again from
// the result when the class differs.
func fitVersion(segs []segment, level Level) (int, error) {
	start := 1
	for {
		needed := 0
		for _, s := range segs {
			needed += 4 + lengthBits(s.mode, start) + s.bits()
		}
		v := sort.Search(41-start, func(i int) bool { return dataBits(start+i, level) >= needed }) + start
		if v > 40 {
			return 0, ErrTooLong
		}
		if versionClass(v) == versionClass(start) {
			return v, nil
		}
		start = v
	}
}

func versionClass(version int) int {
	switch {
	case version < 10:
		return 0
	case version < 27:
		return 1
	default:
		return 2
	}
}
