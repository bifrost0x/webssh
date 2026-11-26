package ldap

import (
	"encoding/hex"
	json "encoding/json/v2"
	"errors"
	"os"
	"testing"
)

type subjectVector struct {
	Raw      string `json:"raw"`
	Subject  string `json:"subject"`
	Rejected bool   `json:"rejected"`
}

// TestCanonicalSubjectMatchesPython replays vectors produced by the Python code
// path (testdata/python_subjects.py). A mismatch would orphan stored
// LDAP identity bindings after the migration.
func TestCanonicalSubjectMatchesPython(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile("testdata/python_subjects.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []subjectVector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) < 3000 {
		t.Fatalf("only %d vectors", len(vectors))
	}
	for _, v := range vectors {
		raw, err := hex.DecodeString(v.Raw)
		if err != nil {
			t.Fatal(err)
		}
		got, err := CanonicalSubject(raw)
		switch {
		case v.Rejected && !errors.Is(err, ErrInvalidSubject):
			t.Errorf("raw %s: want rejection, got %q (%v)", v.Raw, got, err)
		case !v.Rejected && (err != nil || got != v.Subject):
			t.Errorf("raw %s: want %q, got %q (%v)", v.Raw, v.Subject, got, err)
		}
	}
}

func FuzzCanonicalSubject(f *testing.F) {
	for _, seed := range []string{"TRUE", "0x1f", " 42 ", "\xff\x00", "a\x00b"} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		s, err := CanonicalSubject(raw)
		if err != nil {
			return
		}
		if s == "" || len([]rune(s)) > maxSubjectRunes {
			t.Fatalf("accepted invalid subject %q", s)
		}
		again, err := CanonicalSubject(raw)
		if err != nil || again != s {
			t.Fatal("not deterministic")
		}
	})
}
