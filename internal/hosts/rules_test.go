package hosts

import (
	"encoding/json/jsontext"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/bifrost0x/webssh/internal/fault"
)

func TestSortOrderIsNumeric(t *testing.T) {
	var records []record
	for _, order := range []string{"10", "9", "123456789012345678901234567890", "0"} {
		r, err := parseRecord(jsontext.Value(`{"id":"` + order + `","name":"n","group":"G","sort_order":` + order + `}`))
		if err != nil {
			t.Fatal(err)
		}
		records = append(records, r)
	}
	var got []string
	for _, i := range orderedGroup(records, groupKey("g"), nil) {
		got = append(got, records[i].text("id"))
	}
	if want := []string{"0", "9", "10", "123456789012345678901234567890"}; !slices.Equal(got, want) {
		t.Fatalf("order %v, want %v", got, want)
	}
}

func TestUsageListIsBounded(t *testing.T) {
	var profiles []jsontext.Value
	for i := range 21 {
		profiles = append(profiles, jsontext.Value(fmt.Sprintf(
			`{"id":"p%d","name":"host\u0007%d","host":"h.example","username":"u","auth_type":"password","jump_host_id":"2735737b-d93a-4e54-acd5-85b740b63526"}`, i, i)))
	}
	s := seeded(t, Legacy{Profiles: profiles})
	err := s.DeleteJumpHost(t.Context(), oracleUser, jsontext.Value(`"2735737b-d93a-4e54-acd5-85b740b63526"`))
	fe, ok := fault.From(err)
	if !ok || fe.Message != "Jump host is used by 22 profiles (showing first 20)" {
		t.Fatalf("refusal %v", err)
	}
	usages := fe.Details["usages"].([]string)
	if len(usages) != 20 || usages[0] != "Via bastion" || usages[1] != "host�0" {
		t.Fatalf("usages %q", usages)
	}
}

func TestSafeReferenceNameCutsWholeCharacters(t *testing.T) {
	got := safeReferenceName(strings.Repeat("a", 127) + "ü")
	if got != strings.Repeat("a", 127) {
		t.Fatalf("got %q", got)
	}
}

func TestPythonIntAndStrip(t *testing.T) {
	for in, want := range map[string]int64{` 22 `: 22, `+2_2`: 22, `-5`: -5} {
		if n, ok := pyIntString(in); !ok || n != want {
			t.Errorf("int(%q) = %d %v", in, n, ok)
		}
	}
	for _, in := range []string{"", "_1", "1_", "1__0", "0x10", "1.5", "²"} {
		if _, ok := pyIntString(in); ok {
			t.Errorf("int(%q) accepted", in)
		}
	}
	if got := pyStrip("\x1c　 x  \x1f"); got != "x" {
		t.Errorf("strip %q", got)
	}
}
