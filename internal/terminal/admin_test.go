package terminal

import (
	"strings"
	"testing"

	"github.com/bifrost0x/webssh/internal/realtime/protocol"
)

// The administration sees every user's live session with its target and
// ends one of them; the attached page learns the reason and the other
// session stays.
func TestAdminSessions(t *testing.T) {
	t.Parallel()
	m := newManager(t, Config{}, &fakeShells{})
	alice, bob := user(t, 1), user(t, 2)
	first := open(t, m, alice, 1)
	second := open(t, m, bob, 1)
	list := m.AdminSessions()
	if len(list) != 2 || list[0].ID != first.SessionID || list[0].Owner != 1 || list[0].Target != "u@h.example:22" ||
		list[0].Tmux || list[1].Owner != 2 || list[0].Created.After(list[1].Created) {
		t.Fatalf("sessions %+v", list)
	}
	if m.AdminDisconnect("missing") {
		t.Fatal("missing session disconnected")
	}
	if !m.AdminDisconnect(second.SessionID) || m.AdminDisconnect(second.SessionID) {
		t.Fatal("disconnect not exactly once")
	}
	if list := m.AdminSessions(); len(list) != 1 || list[0].ID != first.SessionID {
		t.Fatalf("after disconnect %+v", list)
	}
	var reason string
	for _, ev := range bob.Events(protocol.TypeTerminalClosed) {
		reason += string(ev.Payload)
	}
	if !strings.Contains(reason, reasonAdmin) || !strings.Contains(reason, second.SessionID) {
		t.Fatalf("bob was told %q", reason)
	}
	if len(alice.Events(protocol.TypeTerminalClosed)) != 0 {
		t.Fatal("alice's session was told to close")
	}
}
