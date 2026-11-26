package legacy

import (
	"errors"
	"fmt"
	"time"
	"unicode/utf8"
)

// Incarnation rule of the migration specification (section 2):
// datetime.fromisoformat(text).isoformat() of the stored users.created_at
// text. This is a port of CPython's C implementation
// (Modules/_datetimemodule.c, v3.15.1: datetime_fromisoformat,
// _find_isoformat_datetime_separator, parse_isoformat_date,
// parse_isoformat_time, parse_hh_mm_ss_ff), the code the Python release
// runs. It is deliberately literal, including the C parser's reads of the
// terminating NUL, because the accepted set is defined by that code and
// not by ISO 8601. TestPythonISOFormatDifferential compares it with the
// interpreter.

var errISOFormat = errors.New("legacy: invalid isoformat string")

// pythonDateTime is a parsed value with an optional fixed UTC offset.
type pythonDateTime struct {
	t         time.Time // wall clock fields; location unused
	hasOffset bool
	offset    time.Duration
}

// pythonFromISOFormatToISO returns fromisoformat(s).isoformat().
func pythonFromISOFormatToISO(s string) (string, error) {
	dt, err := pythonFromISOFormat(s)
	if err != nil {
		return "", err
	}
	return dt.isoformat(), nil
}

// cstr reads a byte string like a NUL-terminated C string.
type cstr []byte

func (b cstr) at(i int) byte {
	if i < 0 || i >= len(b) {
		return 0
	}
	return b[i]
}

func (b cstr) digits(p, n int) (int, int, bool) {
	v := 0
	for range n {
		d := b.at(p) - '0'
		if d > 9 {
			return 0, p, false
		}
		v, p = v*10+int(d), p+1
	}
	return v, p, true
}

func pythonFromISOFormat(s string) (pythonDateTime, error) {
	if !utf8.ValidString(s) || utf8.RuneCountInString(s) < 7 {
		return pythonDateTime{}, errISOFormat
	}
	b := cstr(s)
	sep, ok := findSeparator(b)
	if !ok {
		return pythonDateTime{}, errISOFormat
	}
	year, month, day, ok := parseISODate(b, sep)
	var c timeComponents
	if ok && len(b) > sep {
		p := sep
		switch lead := b[p]; {
		case lead&0x80 == 0:
			p++
		case lead&0xf0 == 0xe0:
			p += 3
		case lead&0xf0 == 0xf0:
			p += 4
		default:
			p += 2
		}
		c, ok = parseISOTime(b, p, len(b)-p)
	}
	if !ok {
		return pythonDateTime{}, errISOFormat
	}
	if c.hour == 24 && month >= 1 && month <= 12 && day <= daysIn(year, month) {
		if c.minute != 0 || c.second != 0 || c.micro != 0 {
			return pythonDateTime{}, errISOFormat
		}
		c.hour, day = 0, day+1
		if day > daysIn(year, month) {
			day, month = 1, month+1
			if month > 12 {
				month, year = 1, year+1
			}
		}
	}
	if year < 1 || year > 9999 || month < 1 || month > 12 || day < 1 || day > daysIn(year, month) ||
		c.hour > 23 || c.minute > 59 || c.second > 59 {
		return pythonDateTime{}, errISOFormat
	}
	t := time.Date(year, time.Month(month), day, c.hour, c.minute, c.second, c.micro*1000, time.UTC)
	return pythonDateTime{t: t, hasOffset: c.hasOffset, offset: c.offset}, nil
}

func daysIn(year, month int) int {
	if month < 1 || month > 12 {
		return 0
	}
	return time.Date(year, time.Month(month)+1, 0, 0, 0, 0, 0, time.UTC).Day()
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// findSeparator is _find_isoformat_datetime_separator.
func findSeparator(s cstr) (int, bool) {
	n := len(s)
	if n == 7 {
		return 7, true
	}
	if s.at(4) == '-' {
		if s.at(5) != 'W' {
			return 10, true
		}
		if n > 8 && s.at(8) == '-' {
			if n == 9 {
				return 0, false
			}
			if n > 10 && isDigit(s.at(10)) {
				return 8, true
			}
			return 10, true
		}
		return 8, true
	}
	if s.at(4) != 'W' {
		return 8, true
	}
	idx := 7
	for idx < n && isDigit(s.at(idx)) {
		idx++
	}
	switch {
	case idx < 9:
		return idx, true
	case idx%2 == 0:
		return 7, true
	default:
		return 8, true
	}
}

// parseISODate is parse_isoformat_date; length is the separator position.
func parseISODate(b cstr, length int) (year, month, day int, ok bool) {
	year, p, ok := b.digits(0, 4)
	if !ok {
		return 0, 0, 0, false
	}
	usesSep := b.at(p) == '-'
	if usesSep {
		p++
	}
	if b.at(p) == 'W' {
		week, q, ok := b.digits(p+1, 2)
		if !ok {
			return 0, 0, 0, false
		}
		p, weekday := q, 1
		if p < length {
			if usesSep {
				if b.at(p) != '-' {
					return 0, 0, 0, false
				}
				p++
			}
			if weekday, _, ok = b.digits(p, 1); !ok {
				return 0, 0, 0, false
			}
		}
		return isoWeekToGregorian(year, week, weekday)
	}
	if month, p, ok = b.digits(p, 2); !ok {
		return 0, 0, 0, false
	}
	if usesSep {
		if b.at(p) != '-' {
			return 0, 0, 0, false
		}
		p++
	}
	if day, _, ok = b.digits(p, 2); !ok {
		return 0, 0, 0, false
	}
	return year, month, day, true
}

func isoWeekToGregorian(year, week, day int) (int, int, int, bool) {
	if year < 1 || year > 9999 {
		return 0, 0, 0, false
	}
	if week <= 0 || week >= 53 {
		jan1 := time.Date(year, 1, 1, 0, 0, 0, 0, time.UTC).Weekday()
		leap := daysIn(year, 2) == 29
		if week != 53 || !(jan1 == time.Thursday || (jan1 == time.Wednesday && leap)) {
			return 0, 0, 0, false
		}
	}
	if day <= 0 || day >= 8 {
		return 0, 0, 0, false
	}
	// Monday of ISO week 1 is the Monday on or before 4 January.
	jan4 := time.Date(year, 1, 4, 0, 0, 0, 0, time.UTC)
	monday := jan4.AddDate(0, 0, -((int(jan4.Weekday()) + 6) % 7))
	d := monday.AddDate(0, 0, (week-1)*7+day-1)
	return d.Year(), int(d.Month()), d.Day(), true
}

type timeComponents struct {
	hour, minute, second, micro int
	hasOffset                   bool
	offset                      time.Duration
}

var fractionCorrection = [...]int{100000, 10000, 1000, 100, 10}

// parseHMSF is parse_hh_mm_ss_ff. It returns the C return code: negative
// on error, 1 when the string does not end at the stopping position, 0
// otherwise.
func parseHMSF(b cstr, p, end int) (c [4]int, rv int) {
	hasSep := true
	fraction := false
	for i := range 3 {
		v, q, ok := b.digits(p, 2)
		if !ok {
			return c, -3
		}
		c[i], p = v, q
		ch := b.at(p)
		p++
		if i == 0 {
			hasSep = ch == ':'
		}
		switch {
		case ch == '.' || ch == ',':
			if i < 2 || p >= end {
				return c, -3
			}
			fraction = true
		case p >= end:
			if ch != 0 {
				return c, 1
			}
			return c, 0
		case hasSep && ch == ':':
			if i == 2 {
				return c, -4
			}
			continue
		case !hasSep:
			p--
		default:
			return c, -4
		}
		if fraction {
			break
		}
	}
	toParse := min(end-p, 6)
	if toParse <= 0 {
		return c, -3
	}
	v, q, ok := b.digits(p, toParse)
	if !ok {
		return c, -3
	}
	if toParse < 6 {
		v *= fractionCorrection[toParse-1]
	}
	c[3], p = v, q
	for isDigit(b.at(p)) {
		p++
	}
	if b.at(p) != 0 {
		return c, 1
	}
	return c, 0
}

// parseISOTime is parse_isoformat_time for b[start:start+n].
func parseISOTime(b cstr, start, n int) (timeComponents, bool) {
	var out timeComponents
	end := start + n
	tz := start
	for {
		if ch := b.at(tz); ch == 'Z' || ch == '+' || ch == '-' {
			break
		}
		if tz++; tz >= end {
			break
		}
	}
	c, rv := parseHMSF(b, start, tz)
	if rv < 0 {
		return out, false
	}
	out.hour, out.minute, out.second, out.micro = c[0], c[1], c[2], c[3]
	if tz == end {
		return out, rv != 1
	}
	if b.at(tz) == 'Z' {
		out.hasOffset = true
		return out, b.at(tz+1) == 0
	}
	sign := time.Duration(1)
	if b.at(tz) == '-' {
		sign = -1
	}
	z, rv := parseHMSF(b, tz+1, end)
	if z[0] > 23 || z[1] > 59 || z[2] > 59 || z[3] > 999999 || rv != 0 {
		return out, false
	}
	out.hasOffset = true
	out.offset = sign * (time.Duration(z[0])*time.Hour + time.Duration(z[1])*time.Minute +
		time.Duration(z[2])*time.Second + time.Duration(z[3])*time.Microsecond)
	return out, true
}

// isoformat prints like datetime.isoformat() with the default separator.
func (d pythonDateTime) isoformat() string {
	s := pythonISOFormat(d.t)
	if !d.hasOffset {
		return s
	}
	off, sign := d.offset, "+"
	if off < 0 {
		off, sign = -off, "-"
	}
	h, m := off/time.Hour, (off%time.Hour)/time.Minute
	sec, us := (off%time.Minute)/time.Second, (off%time.Second)/time.Microsecond
	s += fmt.Sprintf("%s%02d:%02d", sign, h, m)
	if sec != 0 || us != 0 {
		s += fmt.Sprintf(":%02d", sec)
	}
	if us != 0 {
		s += fmt.Sprintf(".%06d", us)
	}
	return s
}
