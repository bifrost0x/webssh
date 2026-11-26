package ldapproto

import (
	"encoding/hex"
	json "encoding/json/v2"
	"errors"
	"os"
	"strings"
	"testing"
	"testing/quick"
)

type libldapVectors struct {
	Filters []struct {
		Filter string  `json:"filter"`
		BER    *string `json:"ber"`
	} `json:"filters"`
	Escapes []struct {
		Value   string `json:"value"`
		Escaped string `json:"escaped"`
	} `json:"escapes"`
}

func loadVectors(t *testing.T) libldapVectors {
	t.Helper()
	raw, err := os.ReadFile("testdata/libldap_filters.json")
	if err != nil {
		t.Fatal(err)
	}
	var v libldapVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Filters) < 5000 || len(v.Escapes) < 500 {
		t.Fatalf("too few vectors: %d filters, %d escapes", len(v.Filters), len(v.Escapes))
	}
	return v
}

// TestCompileFilterMatchesLibldap compares every vector of
// testdata/libldap_filters.json (written by libldap_filters.py): a filter
// libldap encodes compiles to the same octets, and a filter libldap
// refuses is refused. The one exception is a filter of white space, which
// libldap encodes as nothing.
func TestCompileFilterMatchesLibldap(t *testing.T) {
	t.Parallel()
	accepted := 0
	for _, v := range loadVectors(t).Filters {
		got, err := CompileFilter(v.Filter)
		switch {
		case v.BER == nil && err == nil:
			t.Errorf("%q: libldap refuses it, compiled to %x", v.Filter, got)
		case v.BER != nil && *v.BER == "":
			if err == nil {
				t.Errorf("%q: libldap encodes nothing, compiled to %x", v.Filter, got)
			}
		case v.BER != nil && err != nil:
			t.Errorf("%q: libldap encodes %s, got %v", v.Filter, *v.BER, err)
		case v.BER != nil && hex.EncodeToString(got) != *v.BER:
			t.Errorf("%q: got %x, libldap %s", v.Filter, got, *v.BER)
		case v.BER != nil:
			accepted++
		}
		if err != nil && !errors.Is(err, ErrFilter) {
			t.Errorf("%q: error %v is not ErrFilter", v.Filter, err)
		}
	}
	if accepted < 1000 {
		t.Errorf("only %d accepted vectors compared", accepted)
	}
}

// TestEscapeFilterValueMatchesPython compares with escape_filter_value of
// app/ldap_service.py.
func TestEscapeFilterValueMatchesPython(t *testing.T) {
	t.Parallel()
	for _, v := range loadVectors(t).Escapes {
		if got := EscapeFilterValue(v.Value); got != v.Escaped {
			t.Errorf("%q: got %q, Python %q", v.Value, got, v.Escaped)
		}
	}
}

func TestCompileFilterBounds(t *testing.T) {
	t.Parallel()
	for name, f := range map[string]string{
		"empty":    "",
		"nul":      "(cn=a\x00)",
		"too long": "(cn=" + strings.Repeat("a", MaxFilterLength) + ")",
		"too deep": strings.Repeat("(!", maxFilterDepth+2) + "(cn=a)" + strings.Repeat(")", maxFilterDepth+2),
	} {
		if _, err := CompileFilter(f); !errors.Is(err, ErrFilter) {
			t.Errorf("%s: want ErrFilter, got %v", name, err)
		}
	}
	// A long escaped user name inside a long template still compiles.
	long := "(&" + strings.Repeat("(objectClass=person)", 200) + "(uid=" + EscapeFilterValue(strings.Repeat("é", 256)) + "))"
	if _, err := CompileFilter(long); err != nil {
		t.Fatalf("long filter: %v", err)
	}
}

// Property: any value escaped with EscapeFilterValue compiles inside an
// equality filter and decodes back to exactly the original bytes. This is
// the injection guarantee for the {username} placeholder.
func TestEscapeFilterValueRoundTrip(t *testing.T) {
	t.Parallel()
	prop := func(v string) bool {
		for _, tmpl := range []string{"(uid=%s)", "uid=%s", "(&(objectClass=person)(uid=%s))"} {
			enc, err := CompileFilter(strings.Replace(tmpl, "%s", EscapeFilterValue(v), 1))
			if err != nil {
				return false
			}
			el, rest, err := parseElement(enc)
			if err != nil || len(rest) != 0 {
				return false
			}
			if el.tag == filterAnd {
				kids, err := el.children()
				if err != nil || len(kids) != 2 {
					return false
				}
				el = kids[1]
			}
			parts, err := el.children()
			if el.tag != filterEquality || err != nil || len(parts) != 2 || string(parts[0].content) != "uid" || string(parts[1].content) != v {
				return false
			}
		}
		return true
	}
	if err := quick.Check(prop, &quick.Config{MaxCount: 20000}); err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{"*", ")(uid=*", "\x00", `\`, "é", "a*b", "\xff\xfe"} {
		if !prop(v) {
			t.Fatalf("round trip failed for %q", v)
		}
	}
}

func FuzzCompileFilter(f *testing.F) {
	for _, s := range []string{"(cn=a)", "(&(a=b)(|(c=d)(!(e=*))))", "(cn=a*b*c)", "(cn:dn:1.2.3:=x)", `(x=\5c)`, "uid=a", "(& (a=b))"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		enc, err := CompileFilter(s)
		if err != nil {
			if !errors.Is(err, ErrFilter) {
				t.Fatalf("%q: unclassified error %v", s, err)
			}
			return
		}
		// Every accepted filter must be one well-formed TLV tree.
		el, rest, err := parseElement(enc)
		if err != nil || len(rest) != 0 {
			t.Fatalf("%q produced malformed BER %x", s, enc)
		}
		if err := walk(el, 0); err != nil {
			t.Fatalf("%q produced malformed children: %v", s, err)
		}
	})
}

func walk(e element, depth int) error {
	if !e.constructed() || depth > maxFilterDepth+2 {
		return nil
	}
	kids, err := e.children()
	if err != nil {
		return err
	}
	for _, k := range kids {
		if err := walk(k, depth+1); err != nil {
			return err
		}
	}
	return nil
}
