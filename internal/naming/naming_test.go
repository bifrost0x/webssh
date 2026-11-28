package naming

import "testing"

func TestKey(t *testing.T) {
	for in, want := range map[string]string{
		"Web Server":     "web server",
		"  WEB SERVER\t": "web server",
		" Box　":          "box",
		"Straße":         "strasse",
		"STRASSE":        "strasse",
		"ẞ":              "ss",
		"Ünïcødé 服务器":    "ünïcødé 服务器",
		"\x1cname\x1f":   "name",
		"inner  spaces":  "inner  spaces",
		"":               "",
	} {
		if got := Key(in); got != want {
			t.Errorf("Key(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestTaken(t *testing.T) {
	names := []string{"Web", "web ", "DB"}
	cases := []struct {
		own  []int
		name string
		want bool
	}{
		{nil, "WEB", true},
		{nil, "Mail", false},
		{[]int{0}, "web", false},  // keeps its own name; the duplicate stays editable
		{[]int{1}, " Web", false}, // the other copy, too
		{[]int{2}, "web", true},   // moving onto a taken name
		{[]int{0}, "db", true},
		{[]int{0, 1}, "WEB", false}, // all records of one id
	}
	for _, c := range cases {
		if got := Taken(names, c.own, c.name); got != c.want {
			t.Errorf("Taken(%v, %q) = %v, want %v", c.own, c.name, got, c.want)
		}
	}
}

func FuzzKey(f *testing.F) {
	for _, s := range []string{"Web Server", " ß ", " x", "İstanbul", "ǅ"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		k := Key(s)
		if Key(k) != k {
			t.Errorf("Key is not idempotent for %q: %q then %q", s, k, Key(k))
		}
		if Key(" "+s+"\t") != k {
			t.Errorf("surrounding space changes the key of %q", s)
		}
	})
}
