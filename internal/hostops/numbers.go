package hostops

import (
	"math"
	"math/big"
	"regexp"
	"strconv"
)

// Numbers in remote output are plain ASCII decimals. The Python release
// used int() and float(), which also accept underscores, Unicode digits
// and "inf"; the collectors never print those, so such values are refused
// (fix, listed in the report). Values arrive stripped.

var (
	intSyntax   = regexp.MustCompile(`^[+-]?[0-9]+$`)
	floatSyntax = regexp.MustCompile(`^[+-]?([0-9]+\.?[0-9]*|\.[0-9]+)([eE][+-]?[0-9]+)?$`)
)

// parseCount parses a non-negative integer of at most limit; ok is false
// for anything else. limit may be the maximum of uint64.
func parseCount(s string, limit uint64) (uint64, bool) {
	s = pyStrip(s)
	if !intSyntax.MatchString(s) {
		return 0, false
	}
	v, ok := new(big.Int).SetString(s, 10)
	if !ok || v.Sign() < 0 || !v.IsUint64() || v.Uint64() > limit {
		return 0, false
	}
	return v.Uint64(), true
}

// parseFloat parses a finite number from 0 to limit.
func parseFloat(s string, limit float64) (float64, bool) {
	s = pyStrip(s)
	if !floatSyntax.MatchString(s) {
		return 0, false
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil || math.IsInf(v, 0) || math.IsNaN(v) || v < 0 || v > limit {
		return 0, false
	}
	return v, true
}
