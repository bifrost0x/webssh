package terminal

import (
	"testing"

	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
)

// The terminal.open result and the restorable list carry the session's
// file source, as ssh_connected and ssh_session_restored did; the
// provider sees the caller and the session's current description.
func TestFileSourceInOpenAndRestore(t *testing.T) {
	m := newManager(t, Config{}, &fakeShells{})
	type seen struct {
		user int64
		info protocol.SessionInfo
	}
	var calls []seen
	m.SetFileSources(func(p principal.Principal, info protocol.SessionInfo) *protocol.FileSource {
		calls = append(calls, seen{p.UserID, info})
		return &protocol.FileSource{SourceID: "sftp-session:" + info.SessionID, Label: info.DisplayName}
	})
	peer := user(t, 1)
	res := open(t, m, peer, 1)
	if fs := res.Info.FileSource; fs == nil || fs.SourceID != "sftp-session:"+res.SessionID {
		t.Fatalf("open result %+v", res.Info.FileSource)
	}
	if len(calls) != 1 || calls[0].user != 1 || calls[0].info.Host != "h.example" || calls[0].info.SessionID != res.SessionID {
		t.Fatalf("provider calls %+v", calls)
	}
	if werr := call(t, m, peer, protocol.TypeTerminalRename, protocol.TerminalRename{SessionID: res.SessionID, Name: "build"}, nil); werr != nil {
		t.Fatal(werr)
	}
	list, _ := m.Restorable(t.Context(), principal.Principal{UserID: 1})
	if len(list) != 1 || list[0].FileSource == nil || list[0].FileSource.Label != "build" {
		t.Fatalf("restorable %+v", list)
	}
}

// Without a provider the member stays absent on the wire.
func TestFileSourceAbsentWithoutProvider(t *testing.T) {
	m := newManager(t, Config{}, &fakeShells{})
	res := open(t, m, user(t, 1), 1)
	if res.Info.FileSource != nil {
		t.Fatalf("file source %+v", res.Info.FileSource)
	}
}
