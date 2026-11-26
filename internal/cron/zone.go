package cron

import (
	"path"
	"strings"
	"time"
	"unicode/utf8"

	// The zone database of the toolchain is the fallback for systems
	// without one (the release image has none); a system database is
	// preferred, as it is by Python's zoneinfo.
	_ "time/tzdata"
)

// LoadZone loads an IANA time zone by its key, with the key rules of
// Python's zoneinfo: a normalized relative path below the zone database,
// at most MaxZoneBytes characters. "Local" and the empty key, which
// time.LoadLocation would map to the host zone or UTC, are refused.
func LoadZone(name string) (*time.Location, error) {
	if name == "" || name == "Local" || !utf8.ValidString(name) || utf8.RuneCountInString(name) > MaxZoneBytes ||
		strings.ContainsRune(name, 0) || strings.HasPrefix(name, "/") {
		return nil, errInvalid
	}
	// zoneinfo refuses keys that normalization would shorten (a/../b,
	// a//b, a/, ./a) and keys that leave the database (../a).
	clean := path.Clean(name)
	if len(clean) != len(name) || clean == ".." || strings.HasPrefix(clean, "../") {
		return nil, errInvalid
	}
	loc, err := time.LoadLocation(name)
	if err != nil {
		return nil, errInvalid
	}
	return loc, nil
}
