package hosts

import (
	json "encoding/json/v2"
	"os"
	"testing"
)

// canonicalHost must agree with canonicalize_hostname of the Python
// release; the vectors of internal/netpolicy are taken from it and hold
// internationalized names.
func TestCanonicalHostMatchesPython(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("../netpolicy/testdata/python_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Canonical []struct {
			In  string `json:"in"`
			OK  bool   `json:"ok"`
			Out string `json:"out"`
		} `json:"canonical"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	idna := 0
	for _, c := range v.Canonical {
		got, ok := canonicalHost(c.In)
		if ok != c.OK || ok && got != c.Out {
			t.Errorf("%+q: Go %q %v, Python %q %v", c.In, got, ok, c.Out, c.OK)
		}
		if c.OK && c.In != c.Out && len(c.Out) > 4 && c.Out[:4] == "xn--" {
			idna++
		}
	}
	if idna == 0 {
		t.Fatal("no internationalized names among the vectors")
	}
}
