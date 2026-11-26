package cron

import (
	"math/bits"
	"slices"
	"time"
)

// days is the number of local dates Next inspects (Horizon).
const days = 366*5 + 1

const (
	// reach bounds the UTC offsets of the zone database (±16 h), so every
	// instant with a given wall time lies within reach of it.
	reach = 17 * 60 * 60
	// sample is the step at which the offsets around a date are read.
	// Zone periods are far longer; a shorter one would be missed.
	sample = 15 * 60
)

// Next returns the first run strictly after after, in UTC. It walks the
// local dates in loc from the date of after for five years: a wall time
// in a spring-forward gap does not exist and is skipped, a wall time in
// an autumn fold runs only at its first occurrence. Without a run in the
// horizon it fails with invalid_schedule, as next_due of
// app/automation_cron.py does.
func (s Schedule) Next(after time.Time, loc *time.Location) (time.Time, error) {
	if loc == nil {
		return time.Time{}, errInvalid
	}
	y, m, d := after.In(loc).Date()
	for offset := range days {
		date := time.Date(y, m, d+offset, 0, 0, 0, 0, time.UTC)
		if s.months&(1<<date.Month()) == 0 || !s.dateMatches(date) {
			continue
		}
		midnight := date.Unix()
		offs := offsets(midnight, loc)
		for hours := s.hours; hours != 0; hours &= hours - 1 {
			h := int64(bits.TrailingZeros32(hours))
			for minutes := s.minutes; minutes != 0; minutes &= minutes - 1 {
				wall := midnight + h*3600 + int64(bits.TrailingZeros64(minutes))*60
				if t, ok := firstInstant(wall, loc, offs); ok && t.After(after) {
					return t, nil
				}
			}
		}
	}
	return time.Time{}, errInvalid
}

// dateMatches applies the day rule: both the day and the weekday field
// must match when either starts with "*", otherwise one of them.
func (s Schedule) dateMatches(date time.Time) bool {
	day := s.days&(1<<date.Day()) != 0
	week := s.weekdays&(1<<date.Weekday()) != 0
	if s.anyDay || s.anyWeekday {
		return day && week
	}
	return day || week
}

// offsets returns the distinct UTC offsets of loc in effect around the
// local date that starts at midnight (seconds of a civil time read as
// UTC). It reads only the offset at instants: time's zone bounds are
// unreliable beyond the last transition of a zone file.
func offsets(midnight int64, loc *time.Location) []int {
	var out []int
	for at := midnight - reach; at <= midnight+24*60*60+reach; at += sample {
		if _, off := time.Unix(at, 0).In(loc).Zone(); !slices.Contains(out, off) {
			out = append(out, off)
		}
	}
	return out
}

// firstInstant returns the earliest instant whose wall clock in loc is
// wall, which is Python's fold=0, or false for a wall time that does not
// exist. An offset o yields the instant wall-o if o is in effect there.
func firstInstant(wall int64, loc *time.Location, offs []int) (time.Time, bool) {
	best, found := int64(0), false
	for _, o := range offs {
		c := wall - int64(o)
		if _, off := time.Unix(c, 0).In(loc).Zone(); off == o && (!found || c < best) {
			best, found = c, true
		}
	}
	return time.Unix(best, 0).UTC(), found
}
