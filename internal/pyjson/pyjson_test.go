package pyjson

import (
	"encoding/json/jsontext"
	"errors"
	"testing"
	"unicode/utf8"
)

func TestLoad(t *testing.T) {
	t.Parallel()
	fffd := string(utf8.RuneError)
	for _, tc := range []struct {
		in, want    string
		lone, dupes bool
	}{
		{in: `{"a": 1, "b": [true, null, "x"]}`, want: `{"a":1,"b":[true,null,"x"]}`},
		{in: `{"a": 1, "b": 2, "a": 3}`, want: `{"a":3,"b":2}`, dupes: true},
		{in: `{"o": {"k": 1, "k": {"k": 2}}}`, want: `{"o":{"k":{"k":2}}}`, dupes: true},
		{in: `["\ud800", "\ud83d\ude80"]`, want: "[\"" + fffd + "\",\"\U0001F680\"]", lone: true},
		{in: `{"\udc00": 1}`, want: "{\"" + fffd + "\":1}", lone: true},
		{in: `{"n": 9007199254740993, "f": 1.50e3, "z": -0}`, want: `{"n":9007199254740993,"f":1.50e3,"z":-0}`},
		{in: `"aA\/"`, want: `"aA/"`},
	} {
		got, rep, err := Load([]byte(tc.in))
		if err != nil {
			t.Fatalf("%s: %v", tc.in, err)
		}
		if string(got) != tc.want || rep.LoneSurrogates != tc.lone || rep.DuplicateNames != tc.dupes {
			t.Errorf("%s: %s %+v", tc.in, got, rep)
		}
		if !got.IsValid() {
			t.Errorf("%s: result is not strict JSON: %s", tc.in, got)
		}
	}
}

func TestLoadRefuses(t *testing.T) {
	t.Parallel()
	deep := make([]byte, 0, 2*MaxDepth+4)
	for range MaxDepth + 2 {
		deep = append(deep, '[')
	}
	for range MaxDepth + 2 {
		deep = append(deep, ']')
	}
	for _, in := range [][]byte{
		[]byte("{\"a\": \"\xff\"}"), []byte(`{"a": 1} x`), []byte(`{"a":}`), []byte(``), []byte(`NaN`), deep,
	} {
		if _, _, err := Load(in); !errors.Is(err, ErrSyntax) {
			t.Errorf("%q: %v", in, err)
		}
	}
}

func TestMembersSetDelete(t *testing.T) {
	t.Parallel()
	v, _, err := Load([]byte(`{"a": 1, "b": {"c": 2}, "d": [1, 2]}`))
	if err != nil {
		t.Fatal(err)
	}
	m, ok := Members(v)
	if !ok || len(m) != 3 || m[1].Name != "b" || string(m[1].Value) != `{"c":2}` {
		t.Fatalf("%+v", m)
	}
	m = Set(m, "a", jsontext.Value(`5`))
	m = Set(m, "e", String("x"))
	m = Delete(m, "b")
	m = Delete(m, "missing")
	if got := string(Object(m)); got != `{"a":5,"d":[1,2],"e":"x"}` {
		t.Fatalf("%s", got)
	}
	if items, ok := Items(jsontext.Value(`[1,{"a":2}]`)); !ok || len(items) != 2 || string(items[1]) != `{"a":2}` {
		t.Fatalf("%v", items)
	}
	if _, ok := Members(jsontext.Value(`[1]`)); ok {
		t.Error("an array has no members")
	}
	if _, ok := Items(jsontext.Value(`{}`)); ok {
		t.Error("an object has no items")
	}
	if g, ok := Get(v, "d"); !ok || string(g) != `[1,2]` {
		t.Error(string(g))
	}
	if _, ok := Get(v, "x"); ok {
		t.Error("absent member found")
	}
}

// Quote matches json.dumps(s) of CPython (ensure_ascii=True).
func TestQuote(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"plain":             `"plain"`,
		"a\"b\\c\n\r\t\b\f": `"a\"b\\c\n\r\t\b\f"`,
		"\x01\x7f":          `"\u0001\u007f"`,
		"\u00fc\u20ac":      `"\u00fc\u20ac"`,
		"\U0001F680":        `"\ud83d\ude80"`,
		"</script>&'":       `"</script>&'"`,
	} {
		if got := Quote(in); got != want {
			t.Errorf("Quote(%q) = %s, want %s", in, got, want)
		}
	}
}

func FuzzLoad(f *testing.F) {
	for _, s := range []string{`{"a":1,"a":2}`, `["\ud800"]`, `{"x":[{"y":"\udfff"}]}`, `1e400`, `"x"`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		v, _, err := Load(in)
		if err != nil {
			return
		}
		if !v.IsValid() {
			t.Fatalf("not strict JSON: %s", v)
		}
		again, rep, err := Load(v)
		if err != nil || string(again) != string(v) || rep.DuplicateNames || rep.LoneSurrogates {
			t.Fatalf("not idempotent: %s -> %s, %+v, %v", v, again, rep, err)
		}
	})
}

func TestLen(t *testing.T) {
	for in, want := range map[string]int{`[]`: 0, `[1,[2,3],{"a":4}]`: 3, `{}`: 0, `{"a":1,"b":[2]}`: 2, `"x"`: 0, `7`: 0, `null`: 0} {
		if got := Len(jsontext.Value(in)); got != want {
			t.Errorf("Len(%s) = %d, want %d", in, got, want)
		}
	}
}

// Values returned by Members, Items and Get share the document's memory
// but cannot overwrite it through append.
func TestValuesDoNotOverwriteTheDocument(t *testing.T) {
	doc := jsontext.Value(`{"a":[1],"b":2}`)
	a, _ := Get(doc, "a")
	_ = append(a, 'x')
	items, _ := Items(a)
	_ = append(items[0], 'y')
	members, _ := Members(doc)
	_ = append(members[0].Value, 'z')
	if string(doc) != `{"a":[1],"b":2}` {
		t.Fatalf("document changed: %s", doc)
	}
}
