package ldapproto

import (
	"bytes"
	"strings"
	"testing"
)

// Property: whatever the user name, the escaped value inside the sign-in
// templates compiles to exactly one assertion that carries the raw bytes.
func FuzzTemplateInjection(f *testing.F) {
	for _, s := range []string{"alice", "*", ")(uid=*", "\x00", "a\\2a", "\xff\xfe", "(|(a=b))", "é", "a)(|(objectClass=*"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, u string) {
		if u == "" || len(u) > 1024 {
			return
		}
		esc := EscapeFilterValue(u)
		got, err := CompileFilter(strings.Replace("(&(objectClass=person)(uid={username}))", "{username}", esc, 1))
		if err != nil {
			t.Fatalf("escaped name %q does not compile: %v", u, err)
		}
		var eq []byte
		eq = appendOctetString(eq, tagOctetString, "uid")
		eq = appendOctetString(eq, tagOctetString, u)
		var pres []byte
		pres = appendOctetString(pres, tagOctetString, "objectClass")
		pres = appendOctetString(pres, tagOctetString, "person")
		want := appendTLV(nil, filterAnd, append(appendTLV(nil, filterEquality, pres), appendTLV(nil, filterEquality, eq)...))
		if !bytes.Equal(got, want) {
			t.Fatalf("injection: %q -> %x want %x", u, got, want)
		}
		sub, err := CompileFilter(strings.Replace("(cn=*{username}*)", "{username}", esc, 1))
		if err != nil {
			t.Fatalf("substring template: %v", err)
		}
		var subs []byte
		subs = appendOctetString(subs, substringAny, u)
		var body []byte
		body = appendOctetString(body, tagOctetString, "cn")
		body = appendTLV(body, tagSequence, subs)
		if w := appendTLV(nil, filterSubstrings, body); !bytes.Equal(sub, w) {
			t.Fatalf("substring injection: %q", u)
		}
	})
}
