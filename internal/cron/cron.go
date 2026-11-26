package cron

import (
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/bifrost0x/webssh/internal/fault"
)

// Schedule is a parsed five-field expression. The zero value matches
// nothing; use Parse.
type Schedule struct {
	minutes  uint64 // bits 0–59
	hours    uint32 // bits 0–23
	days     uint32 // bits 1–31
	months   uint16 // bits 1–12
	weekdays uint8  // bits 0–6, Sunday is 0
	// anyDay and anyWeekday record that the day or weekday field starts
	// with "*"; then both fields must match a date, otherwise either.
	anyDay, anyWeekday bool
}

// errInvalid is the one error of an expression, a zone or a schedule
// without a next run, as in Python (AutomationError('invalid_schedule')).
var errInvalid = fault.New(fault.InvalidSchedule, "The schedule is invalid.")

// bounds are the value ranges of the five fields in order.
var bounds = [5][2]int{{0, 59}, {0, 23}, {1, 31}, {1, 12}, {0, 7}}

// Parse parses a five-field expression: minute, hour, day of month, month
// and weekday (0–7, both 0 and 7 are Sunday). A field is a list of "*",
// "N" or "A-B", each with an optional "/S"; "N/S" runs to the maximum.
// Names, macros and the extensions L, W, # and ? are not supported.
func Parse(expr string) (Schedule, error) {
	if !utf8.ValidString(expr) || utf8.RuneCountInString(expr) > MaxExprBytes {
		return Schedule{}, errInvalid
	}
	fields := strings.FieldsFunc(expr, isSpace)
	if len(fields) != 5 {
		return Schedule{}, errInvalid
	}
	var sets [5]uint64
	for i, f := range fields {
		if strings.Trim(f, "0123456789*/,-") != "" {
			return Schedule{}, errInvalid
		}
		set, ok := field(f, bounds[i][0], bounds[i][1])
		if !ok {
			return Schedule{}, errInvalid
		}
		sets[i] = set
	}
	week := sets[4]
	if week&(1<<7) != 0 {
		week = week&^(1<<7) | 1
	}
	return Schedule{
		minutes: sets[0], hours: uint32(sets[1]), days: uint32(sets[2]), months: uint16(sets[3]), weekdays: uint8(week), // #nosec G115 -- field bounds the bits
		anyDay: strings.HasPrefix(fields[2], "*"), anyWeekday: strings.HasPrefix(fields[4], "*"),
	}, nil
}

// isSpace is the whitespace of Python's str.split(): Unicode white space
// and the separators U+001C to U+001F.
func isSpace(r rune) bool {
	return unicode.IsSpace(r) || r >= 0x1c && r <= 0x1f
}

// field parses one comma-separated field into a bit set of its values.
func field(s string, low, high int) (uint64, bool) {
	var set uint64
	for part := range strings.SplitSeq(s, ",") {
		interval := strings.Split(part, "/")
		if len(interval) > 2 {
			return 0, false
		}
		step := 1
		if len(interval) == 2 {
			var ok bool
			if step, ok = number(interval[1]); !ok {
				return 0, false
			}
		}
		if step < 1 || step > high-low+1 {
			return 0, false
		}
		base := interval[0]
		var start, stop int
		switch {
		case base == "*":
			start, stop = low, high
		case strings.Contains(base, "-"):
			a, b, _ := strings.Cut(base, "-")
			var ok1, ok2 bool
			start, ok1 = number(a)
			stop, ok2 = number(b)
			if !ok1 || !ok2 {
				return 0, false
			}
		default:
			var ok bool
			if start, ok = number(base); !ok {
				return 0, false
			}
			stop = start
			if len(interval) == 2 {
				stop = high
			}
		}
		if low > start || start > stop || stop > high {
			return 0, false
		}
		for v := start; v <= stop; v += step {
			set |= 1 << v
		}
	}
	return set, true
}

// number parses a run of ASCII digits; signs and other characters are
// refused (Parse already allows only digits and "*/,-").
func number(s string) (int, bool) {
	if s == "" || strings.Trim(s, "0123456789") != "" {
		return 0, false
	}
	n, err := strconv.Atoi(s)
	return n, err == nil
}
