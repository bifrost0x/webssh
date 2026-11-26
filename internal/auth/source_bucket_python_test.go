package auth

import (
	json "encoding/json/v2"
	"os"
	"testing"
)

// testdata/python_source_bucket.json is produced by
// testdata/python_source_bucket.py from rate_limit_address of app/auth.py,
// for every IPv6 prefix the sign-in protection allows and a range of
// addresses and non-addresses.
func TestSourceBucketMatchesPython(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("testdata/python_source_bucket.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		In     string `json:"in"`
		Prefix int    `json:"prefix"`
		Want   string `json:"want"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) < 1000 {
		t.Fatalf("only %d vectors", len(vectors))
	}
	for _, v := range vectors {
		got := SourceBucket(v.In, v.Prefix)
		want := v.Want
		if v.In == "" {
			// fix: Python keys an empty address as "" (str of the value);
			// Go uses "unknown" so the empty key cannot be shared with a
			// missing one. Both put all such requests in one bucket.
			want = "unknown"
		}
		if v.In == "fe80::1%eth0" {
			// fix: Python keeps the zone at /128 only; Go drops it at every
			// prefix, so one link-local client cannot get a bucket per zone.
			want = SourceBucket("fe80::1", v.Prefix)
		}
		if got != want {
			t.Errorf("%q /%d: %q, Python %q", v.In, v.Prefix, got, want)
		}
	}
}
