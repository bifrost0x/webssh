package cron

import (
	"testing"
	"time"
)

func FuzzParse(f *testing.F) {
	for _, e := range parseExprs {
		f.Add(e, int64(1767225600), uint8(0))
	}
	f.Fuzz(func(t *testing.T, expr string, after int64, zone uint8) {
		s, err := Parse(expr)
		if err != nil {
			return
		}
		loc, err := LoadZone(zones[int(zone)%len(zones)])
		if err != nil {
			t.Fatal(err)
		}
		at := time.Unix(after%(1<<36), 0)
		next, err := s.Next(at, loc)
		if err != nil {
			return
		}
		if !next.After(at) || next.Sub(at) > Horizon+48*time.Hour {
			t.Fatalf("Next(%s) = %s", at, next)
		}
		local := next.In(loc)
		if s.minutes&(1<<local.Minute()) == 0 || s.hours&(1<<local.Hour()) == 0 ||
			s.months&(1<<local.Month()) == 0 || !s.dateMatches(local) {
			t.Fatalf("%q: run %s does not match", expr, local)
		}
		if local.Second() != 0 && local.Location() == time.UTC {
			t.Fatalf("run %s is not on a minute", local)
		}
	})
}
