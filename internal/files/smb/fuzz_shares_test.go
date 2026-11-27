package smb

import (
	"encoding/json/jsontext"
	"testing"

	"github.com/bifrost0x/webssh/internal/pyjson"
)

// FuzzShareRecord: a stored record from a legacy document never panics
// the validator, and an accepted one has no secret member and fields in
// canonical form.
func FuzzShareRecord(f *testing.F) {
	f.Add(`{"id":"a","name":"N","host":"h","share":"S","domain":"","username":"u","created_at":"t","updated_at":"t"}`)
	f.Add(`{"id":"a","name":" N","host":"H","share":"C$","username":"u","created_at":"t","updated_at":"t","token":1}`)
	f.Fuzz(func(t *testing.T, raw string) {
		v, _, err := pyjson.Load([]byte(raw))
		if err != nil {
			return
		}
		if !validRecord(v) {
			return
		}
		members, _ := pyjson.Members(v)
		for _, m := range members {
			if secretField(m.Name) {
				t.Fatalf("secret member %q accepted", m.Name)
			}
		}
		f, ok := validFields(func(n string) (jsontext.Value, bool) { return pyjson.Get(v, n) })
		if !ok || !ValidShareName(f.Share) {
			t.Fatalf("accepted record has invalid fields: %s", raw)
		}
	})
}
