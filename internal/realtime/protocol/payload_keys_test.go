package protocol

import (
	json "encoding/json/v2"
	"maps"
	"slices"
	"testing"
)

// The members of keys.* are what profile-manager.js sends and reads; the
// list is pinned so a rename on either side fails here.
func TestKeyPayloadMembers(t *testing.T) {
	members := func(v any) []string {
		t.Helper()
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatal(err)
		}
		return slices.Sorted(maps.Keys(m))
	}
	for name, c := range map[string]struct {
		v    any
		want []string
	}{
		"KeySummary":  {KeySummary{}, []string{"encrypted", "filename", "id", "key_type", "name", "uploaded_at", "usable"}},
		"KeysList":    {KeysList{}, []string{"keys"}},
		"KeyResult":   {KeyResult{}, []string{"key"}},
		"KeysUpload":  {KeysUpload{Passphrase: "p", StepUp: "g"}, []string{"key_content", "name", "passphrase", "step_up"}},
		"KeysRename":  {KeysRename{}, []string{"key_id", "name"}},
		"KeysReplace": {KeysReplace{Passphrase: "p", StepUp: "g"}, []string{"key_content", "key_id", "passphrase", "step_up"}},
		"KeysDelete":  {KeysDelete{StepUp: "g"}, []string{"key_id", "step_up"}},
	} {
		if got := members(c.v); !slices.Equal(got, c.want) {
			t.Errorf("%s: %v, want %v", name, got, c.want)
		}
	}
	// The Python release's requests decode as they are.
	var up KeysUpload
	if err := DecodePayload([]byte(`{"name":"k","key_content":"pem"}`), &up); err != nil || up.Name != "k" {
		t.Fatalf("upload_key payload: %v", err)
	}
}
