package cron

import (
	"math/rand/v2"
	"strconv"
	"strings"
	"time"
)

// parseExprs are expressions for the grammar: valid, invalid and the
// edges of every field.
var parseExprs = []string{
	"* * * * *", "0 0 * * *", "*/5 * * * *", "*/60 * * * *", "*/61 * * * *", "*/0 * * * *",
	"0-59 0-23 1-31 1-12 0-7", "60 * * * *", "* 24 * * *", "* * 0 * *", "* * 32 * *", "* * * 0 *",
	"* * * 13 *", "* * * * 8", "* * * * 7", "* * * * 0,7", "5-7 * * * *", "7-5 * * * *",
	"1-2-3 * * * *", "1/2/3 * * * *", "5/15 * * * *", "5-30/10 * * * *", "*/8 * * * 0-7/8",
	"* * * * */9", ",5 * * * *", "5, * * * *", "5,,6 * * * *", "- * * * *", "1- * * * *", "-1 * * * *",
	"*-5 * * * *", "*/ * * * *", "/5 * * * *", "007 * * * *", "0000000000000000000005 * * * *",
	"99999999999999999999 * * * *", "* * * * MON", "@daily", "* * * *", "* * * * * *", "",
	"   ", "\t0\t0\t*\t*\t*\t", " 0 0 * * * ", "0\v0\f*\r*\n*", "0\x1c0\x1d*\x1e*\x1f*",
	"0\u00a00\u2003*\u3000*\u2028*", "0\u200b0 * * *", "+5 * * * *", "5 * * * L", "? * * * *",
	"0 0 L * *", "0 0 1W * *", "0 0 * * 1#2", "\uff11 * * * *", "0 0 * * 5-5", "0 0 31 2 *",
	"0 0 30 2 *", "0 0 29 2 *", "0 0 29 2 1", "0 0 */2 * 1", "0 0 1 * */2", "0 0 1-7 * 1",
	"0 0 * 1-12/12 *", "0 0 * 1-12/13 *", "0 0 1-31/31 * *", "0 0 1-31/32 * *", "0 0-23/24 * * *",
	"0 0-23/25 * * *", "0-59/60 * * * *", strings.Repeat("1,", 61) + "1 * * * *",
	strings.Repeat("1,", 62) + "1 * * * *", strings.Repeat(" ", 120) + "* * * * *",
	strings.Repeat("\u2003", 119) + "* * * * *", strings.Repeat("\u2003", 124) + "* * * * *",
	"* * * * *\x00",
}

var zones = []string{
	"UTC", "Europe/Berlin", "America/New_York", "Australia/Lord_Howe", "Pacific/Chatham",
	"America/Santiago", "Asia/Tehran", "Africa/Casablanca", "Europe/Dublin", "America/St_Johns",
	"Asia/Kathmandu", "Pacific/Kiritimati", "Pacific/Apia", "America/Sao_Paulo", "Asia/Gaza",
	"Antarctica/Troll", "Europe/London", "Etc/GMT+5", "Asia/Kolkata", "America/Havana",
	"Europe/Moscow", "Pacific/Auckland", "America/Godthab", "Asia/Pyongyang",
}

// badZones are keys that Python refuses or that differ from
// time.LoadLocation.
var badZones = []string{
	"", "Local", "utc", "/etc/localtime", "../x", "..", "Europe/../UTC", "Europe//Berlin", "./UTC",
	"UTC/", "Europe", "zone.tab", "tzdata.zi", "leapseconds", " UTC", "a\x00b",
	"+VERSION", "Europe\\Berlin", strings.Repeat("A", 129),
	"Factory", "EST5EDT", "GMT", "Etc/GMT-14", "US/Pacific",
}

// hostZones are keys that only the system zone database may have; the
// embedded database of Go and the tzdata package of Python lack them.
// Whether they load depends on the host (Ubuntu links localtime to
// /etc/localtime and moved posix/ and right/ to tzdata-legacy), so they
// are not recorded but tested against a pinned database (zonedb_test.go).
var hostZones = []string{"localtime", "posix/Europe/Berlin", "right/UTC", "posixrules"}

var nextExprs = []string{
	"*/15 * * * *", "30 2 * * *", "0 2 * * *", "0 3 * * *", "59 1 * * *", "0 1 * * *", "0 0 * * *",
	"59 23 31 12 *", "0 2 29 2 *", "0 0 1 * 1", "0 0 * * 0", "0,30 1-3 * * *", "0 3 * 10 0",
	"0 0 31 2 *", "0 0 13 * 5", "0 12 * * 1-5", "*/7 */5 */3 */2 *", "0 0 29 2 1", "45 23 * * 6",
	"0 0 L * *", "15 0 * * *", "30 0 * 9 *", "0 4 * * 0",
}

// transitions are instants near zone changes of the zones above and of
// ordinary days.
var transitions = []string{
	"2026-03-29T00:30:00Z", "2026-10-25T00:30:00Z", "2026-03-08T06:30:00Z", "2026-11-01T05:30:00Z",
	"2026-04-04T15:00:00Z", "2026-09-26T15:00:00Z", "2011-12-29T09:00:00Z", "2018-11-03T02:30:00Z",
	"2026-04-05T02:30:00Z", "2024-02-29T23:59:59Z", "2026-01-01T00:00:00Z", "1999-12-31T22:59:00Z",
	"2026-03-01T00:00:00Z", "2026-02-15T03:00:00Z", "2037-11-01T05:30:00Z", "1975-06-01T00:00:00Z",
}

// cases are the recorded differential cases, in a fixed order.
func cases() []request {
	var out []request
	for _, e := range parseExprs {
		out = append(out, request{Op: "parse", Expr: e, Zone: "UTC"})
	}
	for _, z := range append(append([]string{}, zones...), badZones...) {
		out = append(out, request{Op: "parse", Expr: "* * * * *", Zone: z})
	}
	for _, z := range zones[:12] {
		for _, e := range nextExprs[:16] {
			for _, at := range transitions[:10] {
				ts, err := time.Parse(time.RFC3339, at)
				if err != nil {
					panic(err)
				}
				out = append(out, request{Op: "next", Expr: e, Zone: z, After: ts.Unix(), N: 4})
			}
		}
	}
	// A year of runs across the transitions (the scheduler preview).
	year := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).Unix()
	for _, z := range []string{"Europe/Berlin", "America/New_York", "Australia/Lord_Howe", "Pacific/Chatham"} {
		for _, e := range []string{"*/30 * * * *", "15 2 * * *", "0 1,2,3 * * 0"} {
			n := 365
			if strings.HasPrefix(e, "*/30") {
				n = 365 * 48
			}
			out = append(out, request{Op: "next", Expr: e, Zone: z, After: year, N: n})
		}
	}
	rng := rand.New(rand.NewPCG(20261127, 1)) // #nosec G404 -- test data
	for range 400 {
		out = append(out, randomCase(rng))
	}
	return out
}

// randomCase builds an expression from the grammar, mostly valid.
func randomCase(rng *rand.Rand) request {
	part := func(low, high int) string {
		n := func() int { return low + rng.IntN(high-low+2) - rng.IntN(2) }
		var s string
		switch rng.IntN(6) {
		case 0:
			s = "*"
		case 1, 2:
			s = itoa(n())
		case 3:
			a, b := n(), n()
			if a > b && rng.IntN(4) > 0 {
				a, b = b, a
			}
			s = itoa(a) + "-" + itoa(b)
		case 4:
			s = "*/" + itoa(1+rng.IntN(high-low+2))
		default:
			s = itoa(n()) + "/" + itoa(rng.IntN(high-low+3))
		}
		return s
	}
	var fields []string
	for _, b := range bounds {
		f := part(b[0], b[1])
		for rng.IntN(4) == 0 {
			f += "," + part(b[0], b[1])
		}
		fields = append(fields, f)
	}
	expr := strings.Join(fields, " ")
	zone := zones[rng.IntN(len(zones))]
	after := 31536000 + rng.Int64N(4102444800-31536000)
	return request{Op: "next", Expr: expr, Zone: zone, After: after, AfterUS: rng.Int64N(1_000_000), N: 1 + rng.IntN(5)}
}

func itoa(n int) string { return strconv.Itoa(n) }
