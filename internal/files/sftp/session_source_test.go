package sftp

import (
	"encoding/json"
	"testing"

	"github.com/bifrost0x/webssh/internal/ssh/client"
)

// SessionSource is _public_file_source of a session before its first SFTP
// channel: the SFTP defaults without chmod, the display name or
// user@host as label.
func TestSessionSource(t *testing.T) {
	fs, err := SessionSource("0f7c", Session{Hop: client.Hop{Host: "lab.example", Port: 2222, User: "ops"}})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(fs)
	want := `{"source_id":"sftp-session:0f7c","kind":"sftp","label":"ops@lab.example","endpoint":"lab.example:2222",` +
		`"protocol":"SFTP","capabilities":["list","read","write","create-file","mkdir","rename","delete","preview","edit","recursive","remote-transfer"],` +
		`"ephemeral":false,"security":{"host_key_verified":true},"access":{}}`
	if string(raw) != want {
		t.Fatalf("descriptor\n got %s\nwant %s", raw, want)
	}
	named, err := SessionSource("0f7c", Session{Name: "build", Hop: client.Hop{Host: "lab.example", Port: 22, User: "ops"}})
	if err != nil || named.Label != "build" || named.Endpoint != "lab.example:22" {
		t.Fatalf("named %+v %v", named, err)
	}
	for _, bad := range []string{"", "a:b", "-x", string(make([]byte, 129))} {
		if _, err := SessionSource(bad, Session{}); err == nil {
			t.Errorf("handle %q accepted", bad)
		}
	}
}
