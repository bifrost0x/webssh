package files_test

import (
	"bytes"
	"context"
	json "encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/files"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
	"github.com/bifrost0x/webssh/internal/realtime/protocol/protocoltest"
)

// A large editor answer does not travel through the realtime connection:
// the page fetches it once over HTTP, only in the browser session that
// opened it.
func TestLargeEditorAnswerIsHandedOff(t *testing.T) {
	t.Parallel()
	f := newFixture(t, files.Options{HandoffInline: 4096})
	big := bytes.Repeat([]byte("line of text\n"), 1000)
	f.b.PutFile("/big.txt", big)
	f.b.PutFile("/small.txt", []byte("small\n"))
	var open protocol.Route
	for _, r := range f.svc.Routes() {
		if r.Type == protocol.TypeFilesEditOpen {
			open = r
		}
	}
	peer := protocoltest.NewPeer(t, alice)
	edit := func(path string) protocol.FilesEditData {
		t.Helper()
		raw, perr := protocoltest.Call(context.Background(), open, peer, map[string]any{"source_id": f.id, "request_id": "r1", "path": path})
		if perr != nil {
			t.Fatalf("%s: %+v", path, perr)
		}
		var out protocol.FilesEditData
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	if small := edit("/small.txt"); small.Handoff != "" || small.Content != "small\n" {
		t.Fatalf("small answer %+v", small)
	}
	parked := edit("/big.txt")
	if parked.Handoff == "" || parked.Content != "" || parked.OriginalBytes != "" || parked.Size != int64(len(big)) || parked.RequestID != "r1" {
		t.Fatalf("parked answer %+v", parked)
	}
	fetch := func(p principal.Principal, token string) (int, protocol.FilesEditData) {
		req := httptest.NewRequestWithContext(principal.With(context.Background(), p), http.MethodGet, "/api/files/handoff/"+token, nil)
		req.SetPathValue("token", token)
		rec := httptest.NewRecorder()
		f.svc.HandoffHTTP(rec, req)
		var out protocol.FilesEditData
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		if rec.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("handoff may be cached")
		}
		return rec.Code, out
	}
	otherSession := alice
	otherSession.SessionID = "other"
	if code, _ := fetch(otherSession, parked.Handoff); code != http.StatusNotFound {
		t.Fatalf("another session got the answer: %d", code)
	}
	code, full := fetch(alice, parked.Handoff)
	if code != http.StatusOK || full.Content != string(big) || full.Revision == "" || full.Handoff != "" {
		t.Fatalf("handed off %d %+v", code, full.Handoff)
	}
	if code, _ := fetch(alice, parked.Handoff); code != http.StatusNotFound {
		t.Fatalf("answer handed out twice: %d", code)
	}
	// A revocation drops what is parked for the session.
	again := edit("/big.txt")
	f.svc.Revoke(principal.Revocation{UserID: alice.UserID, SessionID: alice.SessionID})
	if code, _ := fetch(alice, again.Handoff); code != http.StatusNotFound {
		t.Fatalf("parked answer survives the revocation: %d", code)
	}
}

// The parked bytes are bounded for all users: a full budget is busy.
func TestHandoffBudget(t *testing.T) {
	t.Parallel()
	f := newFixture(t, files.Options{HandoffInline: 1024, HandoffBudget: 160 << 10})
	f.b.PutFile("/big.txt", []byte(strings.Repeat("x", 40<<10)))
	var open protocol.Route
	for _, r := range f.svc.Routes() {
		if r.Type == protocol.TypeFilesEditOpen {
			open = r
		}
	}
	peer := protocoltest.NewPeer(t, alice)
	call := func() *protocol.Error {
		_, perr := protocoltest.Call(context.Background(), open, peer, map[string]any{"source_id": f.id, "request_id": "r1", "path": "/big.txt"})
		return perr
	}
	if perr := call(); perr != nil {
		t.Fatal(perr)
	}
	if perr := call(); perr == nil || perr.Code != fault.Busy {
		t.Fatalf("budget not applied: %+v", perr)
	}
}
