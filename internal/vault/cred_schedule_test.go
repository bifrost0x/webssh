package vault

import (
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"os"
	"testing"
)

// The Python vectors of profile_fingerprint hold for raw records too.
func TestRecordFingerprintVectors(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile("testdata/fingerprint-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		Record      jsontext.Value `json:"record"`
		Fingerprint string         `json:"fingerprint"`
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) == 0 {
		t.Fatal("no vectors")
	}
	for i, v := range vectors {
		got, ok := RecordFingerprint(v.Record)
		if !ok || got != v.Fingerprint {
			t.Errorf("vector %d: %q, %v; want %q", i, got, ok, v.Fingerprint)
		}
	}
}

func TestRecordFingerprintRefusesUnfrozenValues(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{`[]`, `"p"`, `{"id":"p","port":22.5}`} {
		if _, ok := RecordFingerprint(jsontext.Value(raw)); ok {
			t.Errorf("%s: accepted", raw)
		}
	}
	// An extra member such as the frozen route does not take part.
	a, _ := RecordFingerprint(jsontext.Value(`{"id":"p","host":"h"}`))
	b, _ := RecordFingerprint(jsontext.Value(`{"id":"p","host":"h","route":{"id":"jump:j"}}`))
	if a != b {
		t.Error("the route member changed the fingerprint")
	}
}

func TestScheduleBindingIsCanonical(t *testing.T) {
	t.Parallel()
	a := ScheduleBinding("inc", "rev", map[string][2]string{"b": {"g2", "v2"}, "a": {"g1", "v1"}})
	want := `{"incarnation":"inc","policy":"rev","records":{"a":["g1","v1"],"b":["g2","v2"]}}`
	if string(a) != want {
		t.Fatalf("%s", a)
	}
	if string(ScheduleBinding("inc", "rev", nil)) != `{"incarnation":"inc","policy":"rev","records":{}}` {
		t.Fatal("empty binding")
	}
}
