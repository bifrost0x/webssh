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

func TestSubjectMayBeTruncated(t *testing.T) {
	for _, s := range []string{"0", "7", "True", "False", "-3", "1234567"} {
		if !SubjectMayBeTruncated(s) {
			t.Errorf("%q not reported", s)
		}
	}
	for _, s := range []string{"", "b64:AAAA", "alice", "07", "1.5", "true", "0x1f", "12a"} {
		if SubjectMayBeTruncated(s) {
			t.Errorf("%q reported", s)
		}
	}
	// Every legacy subject Subjects returns for a value with a NUL is
	// one SubjectMayBeTruncated reports.
	for _, raw := range [][]byte{[]byte("7\x00abc"), []byte("TRUE\x00x"), []byte(" 0x1f\x00"), []byte("-1_0\x00z")} {
		_, legacy, err := Subjects(raw)
		if err != nil || legacy == "" || !SubjectMayBeTruncated(legacy) {
			t.Errorf("%q: legacy %q %v", raw, legacy, err)
		}
	}
}
