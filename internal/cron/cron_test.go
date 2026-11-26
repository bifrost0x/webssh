package cron

import (
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
)

func mustZone(t *testing.T, name string) *time.Location {
	t.Helper()
	loc, err := LoadZone(name)
	if err != nil {
		t.Fatalf("LoadZone(%q): %v", name, err)
	}
	return loc
}

func utc(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

func runs(t *testing.T, expr, zone, after string, n int) []string {
	t.Helper()
	s, err := Parse(expr)
	if err != nil {
		t.Fatalf("Parse(%q): %v", expr, err)
	}
	loc := mustZone(t, zone)
	at := utc(after)
	var out []string
	for range n {
		if at, err = s.Next(at, loc); err != nil {
			t.Fatalf("Next: %v", err)
		}
		out = append(out, at.Format(time.RFC3339))
	}
	return out
}

func TestNextDaylightSaving(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, expr, zone, after string
		want                    []string
	}{
		// 02:30 does not exist on 29 March 2026 in Berlin: skipped.
		{"spring gap", "30 2 * * *", "Europe/Berlin", "2026-03-28T12:00:00Z",
			[]string{"2026-03-30T00:30:00Z", "2026-03-31T00:30:00Z"}},
		// 02:30 exists twice on 25 October 2026: only the first runs.
		{"autumn fold", "30 2 * * *", "Europe/Berlin", "2026-10-24T12:00:00Z",
			[]string{"2026-10-25T00:30:00Z", "2026-10-26T01:30:00Z"}},
		// After the first occurrence, the second one is not a run.
		{"inside the fold", "45 2 * * *", "Europe/Berlin", "2026-10-25T00:50:00Z",
			[]string{"2026-10-26T01:45:00Z"}},
		{"hourly over the gap", "0 * * * *", "Europe/Berlin", "2026-03-29T00:30:00Z",
			[]string{"2026-03-29T01:00:00Z", "2026-03-29T02:00:00Z"}},
		{"hourly over the fold", "0 * * * *", "Europe/Berlin", "2026-10-24T23:30:00Z",
			[]string{"2026-10-25T00:00:00Z", "2026-10-25T02:00:00Z", "2026-10-25T03:00:00Z"}},
		// Lord Howe shifts by 30 minutes.
		{"half-hour shift", "15 2 * * *", "Australia/Lord_Howe", "2026-10-03T12:00:00Z",
			[]string{"2026-10-04T15:15:00Z"}},
		{"new york gap", "30 2 * * *", "America/New_York", "2026-03-07T12:00:00Z",
			[]string{"2026-03-09T06:30:00Z"}},
		{"utc", "*/20 * * * *", "UTC", "2026-01-01T00:00:00Z",
			[]string{"2026-01-01T00:20:00Z", "2026-01-01T00:40:00Z", "2026-01-01T01:00:00Z"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			got := runs(t, c.expr, c.zone, c.after, len(c.want))
			for i := range c.want {
				if got[i] != c.want[i] {
					t.Fatalf("runs %v, want %v", got, c.want)
				}
			}
		})
	}
}

func TestNextDayRule(t *testing.T) {
	t.Parallel()
	// 2026-02-01 is a Sunday; the 13th of February 2026 is a Friday.
	cases := []struct{ expr, want string }{
		{"0 0 13 * 5", "2026-02-06T00:00:00Z"},  // the 13th or a Friday
		{"0 0 * * 5", "2026-02-06T00:00:00Z"},   // Fridays
		{"0 0 */2 * 5", "2026-02-13T00:00:00Z"}, // odd days that are Fridays
		{"0 0 13 * *", "2026-02-13T00:00:00Z"},
		{"0 0 1 * 7", "2026-02-08T00:00:00Z"}, // the 1st (past) or a Sunday
		{"0 0 29 2 1", "2026-02-02T00:00:00Z"},
		{"0 0 29 2 *", "2028-02-29T00:00:00Z"},
	}
	for _, c := range cases {
		if got := runs(t, c.expr, "UTC", "2026-02-01T00:00:00Z", 1)[0]; got != c.want {
			t.Errorf("%q: %s, want %s", c.expr, got, c.want)
		}
	}
}

func TestNextStrictlyAfter(t *testing.T) {
	t.Parallel()
	if got := runs(t, "0 * * * *", "UTC", "2026-01-01T05:00:00Z", 1)[0]; got != "2026-01-01T06:00:00Z" {
		t.Fatalf("got %s", got)
	}
	s, _ := Parse("0 * * * *")
	got, err := s.Next(utc("2026-01-01T04:59:59Z").Add(999*time.Millisecond), time.UTC)
	if err != nil || !got.Equal(utc("2026-01-01T05:00:00Z")) {
		t.Fatalf("got %s, %v", got, err)
	}
}

func TestNextWithoutRun(t *testing.T) {
	t.Parallel()
	for _, expr := range []string{"0 0 31 2 *", "0 0 30 2 *", "0 0 31 4,6,9,11 *"} {
		s, err := Parse(expr)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.Next(utc("2026-01-01T00:00:00Z"), time.UTC); !fault.Is(err, fault.InvalidSchedule) {
			t.Errorf("%q: %v", expr, err)
		}
	}
	s, _ := Parse("* * * * *")
	if _, err := s.Next(time.Now(), nil); !fault.Is(err, fault.InvalidSchedule) {
		t.Errorf("nil zone: %v", err)
	}
	if _, err := (Schedule{}).Next(time.Now(), time.UTC); !fault.Is(err, fault.InvalidSchedule) {
		t.Errorf("zero schedule: %v", err)
	}
}

func TestParseRefuses(t *testing.T) {
	t.Parallel()
	for _, expr := range []string{
		"", "* * * *", "* * * * * *", "60 * * * *", "* * * * 8", "*/0 * * * *", "*/61 * * * *",
		"7-5 * * * *", "1-2-3 * * * *", "1/2/3 * * * *", ",5 * * * *", "-1 * * * *", "+5 * * * *",
		"* * * * MON", "@daily", "0 0 L * *", "0 0 * * 1#2", "? * * * *", "\uff11 * * * *", "\xff * * * *",
		"0\u200b0 * * *", "99999999999999999999 * * * *",
	} {
		if _, err := Parse(expr); !fault.Is(err, fault.InvalidSchedule) {
			t.Errorf("Parse(%q) = %v", expr, err)
		}
	}
}

func TestLoadZone(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"", "Local", "utc", "/etc/localtime", "../x", "Europe/../UTC",
		"Europe//Berlin", "./UTC", "UTC/", "Europe", "zone.tab", "a\x00b", " UTC"} {
		if _, err := LoadZone(name); !fault.Is(err, fault.InvalidSchedule) {
			t.Errorf("LoadZone(%q) = %v", name, err)
		}
	}
	if loc := mustZone(t, "Europe/Berlin"); loc.String() != "Europe/Berlin" {
		t.Fatalf("loaded %s", loc)
	}
}
