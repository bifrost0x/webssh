package webauthn

import (
	"bytes"
	"encoding/json/jsontext"
	"testing"
)

// The options JSON of py_webauthn 3.0.1 for the same input, as the Python
// release sent it (generated with options_to_json; the route appended
// "ceremony").
const (
	pyCreation     = `{"rp": {"name": "WebSSH", "id": "localhost"}, "user": {"id": "Nw", "name": "user7", "displayName": "user7"}, "challenge": "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBw", "pubKeyCredParams": [{"type": "public-key", "alg": -8}, {"type": "public-key", "alg": -7}, {"type": "public-key", "alg": -257}], "timeout": 60000, "excludeCredentials": [{"id": "AQI", "type": "public-key"}], "authenticatorSelection": {"residentKey": "required", "requireResidentKey": true, "userVerification": "required"}, "attestation": "none", "ceremony": "c"}`
	pyRequest      = `{"challenge": "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBw", "timeout": 60000, "rpId": "localhost", "allowCredentials": [{"id": "AQI", "type": "public-key"}], "userVerification": "required"}`
	pyRequestEmpty = `{"challenge": "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBw", "timeout": 60000, "rpId": "localhost", "allowCredentials": [], "userVerification": "required"}`
)

func compact(t *testing.T, s string) string {
	t.Helper()
	v := jsontext.Value(s)
	if err := v.Compact(); err != nil {
		t.Fatal(err)
	}
	return string(v)
}

func TestOptionsMatchPython(t *testing.T) {
	t.Parallel()
	ch := bytes.Repeat([]byte{7}, 64)
	rp := RelyingParty{ID: "localhost", Name: "WebSSH", Origin: "http://localhost"}
	got, err := rp.creationJSON(7, "user7", ch, [][]byte{{1, 2}}, "c")
	if err != nil || string(got) != compact(t, pyCreation) {
		t.Fatalf("creation options\n got %s\nwant %s (%v)", got, compact(t, pyCreation), err)
	}
	got, err = rp.requestJSON(ch, [][]byte{{1, 2}})
	if err != nil || string(got) != compact(t, pyRequest) {
		t.Fatalf("request options\n got %s\nwant %s (%v)", got, compact(t, pyRequest), err)
	}
	got, err = rp.requestJSON(ch, nil)
	if err != nil || string(got) != compact(t, pyRequestEmpty) {
		t.Fatalf("request options without credentials\n got %s (%v)", got, err)
	}
	got, _ = rp.creationJSON(7, "user7", ch, nil, "c")
	if !bytes.Contains(got, []byte(`"excludeCredentials":[]`)) {
		t.Fatalf("empty exclude list: %s", got)
	}
}

func TestNormalizeName(t *testing.T) {
	t.Parallel()
	long := ""
	for range 90 {
		long += "日"
	}
	for in, want := range map[string]string{
		"":         "Passkey",
		"  \t ":    "Passkey",
		" Laptop ": "Laptop",
		long:       long[:80*3],
		" Key　":    "Key",
	} {
		if got := NormalizeName(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}
