package audit

import (
	"errors"
	"strings"
	"time"
)

var errTimestamp = errors.New("audit: invalid timestamp")

// parseTimestamp is _parse_timestamp of app/audit_export.py:
// datetime.fromisoformat(value.replace("Z", "+00:00")), naive values read
// as UTC, the result in UTC with microsecond precision. It accepts the
// calendar dates (extended YYYY-MM-DD and basic YYYYMMDD), a time of day
// after any one separator character (HH, HH:MM, HH:MM:SS, HHMM, HHMMSS,
// 24:00 as the next midnight), a fraction after "." or "," cut to
// microseconds, and an offset ±HH, ±HH:MM, ±HHMM or ±HH:MM:SS. Week and
// ordinal dates, which no audit line and no form of the page uses, are
// refused.
func parseTimestamp(value string) (time.Time, error) {
	s := strings.ReplaceAll(value, "Z", "+00:00")
	date, rest, err := isoDate(s)
	if err != nil {
		return time.Time{}, err
	}
	if rest == "" {
		return date, nil
	}
	if len(rest) < 3 {
		return time.Time{}, errTimestamp
	}
	clock, zone := rest[1:], ""
	if i := strings.IndexAny(clock, "+-"); i >= 0 {
		clock, zone = clock[:i], clock[i:]
	}
	t, err := isoClock(date, clock)
	if err != nil {
		return time.Time{}, err
	}
	if zone != "" {
		off, err := isoOffset(zone)
		if err != nil {
			return time.Time{}, err
		}
		t = t.Add(-off)
	}
	return t.UTC(), nil
}

func num(s string) (int, bool) {
	if s == "" {
		return 0, false
	}
	n := 0
	for _, c := range []byte(s) {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
	}
	return n, true
}

func isoDate(s string) (time.Time, string, error) {
	var y, m, d int
	var ok1, ok2, ok3 bool
	var rest string
	switch {
	case len(s) >= 10 && s[4] == '-' && s[7] == '-':
		y, ok1 = num(s[:4])
		m, ok2 = num(s[5:7])
		d, ok3 = num(s[8:10])
		rest = s[10:]
	case len(s) >= 8:
		y, ok1 = num(s[:4])
		m, ok2 = num(s[4:6])
		d, ok3 = num(s[6:8])
		rest = s[8:]
	}
	if !ok1 || !ok2 || !ok3 || y < 1 || m < 1 || m > 12 || d < 1 {
		return time.Time{}, "", errTimestamp
	}
	t := time.Date(y, time.Month(m), d, 0, 0, 0, 0, time.UTC)
	if t.Day() != d {
		return time.Time{}, "", errTimestamp
	}
	return t, rest, nil
}

// fraction parses digits after the separator, keeping microseconds.
func fraction(s string) (int, bool) {
	if s == "" {
		return 0, false
	}
	us, scale := 0, 100000
	for _, c := range []byte(s) {
		if c < '0' || c > '9' {
			return 0, false
		}
		us += int(c-'0') * scale
		scale /= 10
	}
	return us, true
}

func isoClock(date time.Time, s string) (time.Time, error) {
	us := 0
	if i := strings.IndexAny(s, ".,"); i >= 0 {
		var ok bool
		if us, ok = fraction(s[i+1:]); !ok || i < 6 {
			return time.Time{}, errTimestamp
		}
		s = s[:i]
	}
	var parts []string
	if strings.Contains(s, ":") {
		parts = strings.Split(s, ":")
	} else {
		for i := 0; i < len(s); i += 2 {
			parts = append(parts, s[i:min(i+2, len(s))])
		}
	}
	if len(parts) == 0 || len(parts) > 3 {
		return time.Time{}, errTimestamp
	}
	var v [3]int
	for i, p := range parts {
		n, ok := num(p)
		if !ok || len(p) != 2 {
			return time.Time{}, errTimestamp
		}
		v[i] = n
	}
	if us != 0 && len(parts) != 3 {
		return time.Time{}, errTimestamp
	}
	h, mi, sec := v[0], v[1], v[2]
	if h == 24 && mi == 0 && sec == 0 && us == 0 {
		return date.AddDate(0, 0, 1), nil
	}
	if h > 23 || mi > 59 || sec > 59 {
		return time.Time{}, errTimestamp
	}
	return date.Add(time.Duration(h)*time.Hour + time.Duration(mi)*time.Minute +
		time.Duration(sec)*time.Second + time.Duration(us)*time.Microsecond), nil
}

func isoOffset(s string) (time.Duration, error) {
	sign := time.Duration(1)
	if s[0] == '-' {
		sign = -1
	}
	t, err := isoClock(time.Time{}, s[1:])
	if err != nil {
		return 0, err
	}
	off := t.Sub(time.Time{})
	if off >= 24*time.Hour {
		return 0, errTimestamp
	}
	return sign * off, nil
}
