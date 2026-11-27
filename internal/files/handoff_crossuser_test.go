package files_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	json "encoding/json/v2"

	"github.com/bifrost0x/webssh/internal/files"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
	"github.com/bifrost0x/webssh/internal/realtime/protocol/protocoltest"
)

// RS8-H20: another user, even one that claims the owner's session id,
// does not get a parked editor answer and does not use it up.
func TestHandoffOfAnotherUserIsNotFound(t *testing.T) {
	t.Parallel()
	f := newFixture(t, files.Options{HandoffInline: 4096})
	f.b.PutFile("/big.txt", bytes.Repeat([]byte("line of text\n"), 1000))
	var open protocol.Route
	for _, r := range f.svc.Routes() {
		if r.Type == protocol.TypeFilesEditOpen {
			open = r
		}
	}
	raw, perr := protocoltest.Call(context.Background(), open, protocoltest.NewPeer(t, alice), map[string]any{"source_id": f.id, "request_id": "r1", "path": "/big.txt"})
	if perr != nil {
		t.Fatalf("%+v", perr)
	}
	var parked protocol.FilesEditData
	if err := json.Unmarshal(raw, &parked); err != nil || parked.Handoff == "" {
		t.Fatalf("not parked: %v %+v", err, parked)
	}
	fetch := func(p principal.Principal) int {
		req := httptest.NewRequestWithContext(principal.With(context.Background(), p), http.MethodGet, "/api/files/handoff/"+parked.Handoff, nil)
		req.SetPathValue("token", parked.Handoff)
		rec := httptest.NewRecorder()
		f.svc.HandoffHTTP(rec, req)
		return rec.Code
	}
	sameSession := bob
	sameSession.SessionID = alice.SessionID
	for _, p := range []principal.Principal{bob, sameSession} {
		if code := fetch(p); code != http.StatusNotFound {
			t.Fatalf("user %d in session %q got the answer: %d", p.UserID, p.SessionID, code)
		}
	}
	if code := fetch(alice); code != http.StatusOK {
		t.Fatalf("the owner lost the answer to the refused attempts: %d", code)
	}
}
