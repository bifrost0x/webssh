package ldapproto

import (
	"errors"
	"strings"
	"testing"
)

// A directory (or anyone holding its certificate) must not make one
// search retain any number of continuation references (RS2-05).
func TestSearchReferencesBounded(t *testing.T) {
	big := "ldap://x/" + strings.Repeat("a", 900<<10)
	s := searchServer(false, func(id int64) [][]byte {
		out := make([][]byte, 0, 66)
		out = append(out, referenceMessage(id, "ldap://ref.example.test/dc=x"))
		ref := referenceMessage(id, big)
		for range 64 {
			out = append(out, ref)
		}
		return append(out, response(id, opSearchDone, ResultSuccess))
	})
	c, err := dialFake(t, s, "ldap://ldap.example.test")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	filter, _ := CompileFilter("(a=1)")
	res, err := c.Search(t.Context(), SearchRequest{BaseDN: "dc=x", Scope: ScopeSubtree, SizeLimit: 2, Filter: filter})
	if err != nil {
		t.Fatal(err)
	}
	total := 0
	for _, r := range res.References {
		total += len(r)
	}
	if total > maxReferenceBytes || len(res.References) != 1 {
		t.Fatalf("search retained %d references, %d bytes", len(res.References), total)
	}
}

// An endless stream of references ends the search as malformed.
func TestSearchMessageCountBounded(t *testing.T) {
	s := searchServer(false, func(id int64) [][]byte {
		out := make([][]byte, 0, maxSearchOtherMessages+2)
		ref := referenceMessage(id, "ldap://ref.example.test/dc=x")
		for range maxSearchOtherMessages + 1 {
			out = append(out, ref)
		}
		return append(out, response(id, opSearchDone, ResultSuccess))
	})
	c, err := dialFake(t, s, "ldap://ldap.example.test")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	filter, _ := CompileFilter("(a=1)")
	_, err = c.Search(t.Context(), SearchRequest{BaseDN: "dc=x", Scope: ScopeSubtree, SizeLimit: 2, Filter: filter})
	if !errors.Is(err, ErrMalformed) {
		t.Fatalf("err = %v, want ErrMalformed", err)
	}
}
