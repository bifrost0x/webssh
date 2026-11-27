package terminal

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/bifrost0x/webssh/internal/realtime/protocol"
	"github.com/bifrost0x/webssh/internal/realtime/protocol/protocoltest"
	"github.com/bifrost0x/webssh/internal/ssh/client"
)

// Turning the tailnet block on detaches every ordinary session whose route
// the block now refuses, the way an administrator disconnect does: tmux
// keeps running, the row is marked not connected and the owner learns the
// reason (close_restricted_tailnet_connections). A session on an allowed
// route and a Tailscale SSH session stay open.
func TestCloseRestrictedRoutes(t *testing.T) {
	r := newTmuxRig(t)
	node := netip.MustParseAddr("100.100.100.10")
	lan := netip.MustParseAddr("192.168.1.10")
	routes := []*fakeHost{
		{route: client.Route{Peer: node}, routed: true},
		{route: client.Route{Peer: lan}, routed: true},
		{routed: false}, // dialled by the Tailscale SSH variant
		{route: client.Route{Peer: lan, Onward: []string{"100.100.100.10"}}, routed: true},
	}
	next := 0
	r.next = func() *fakeHost { h := routes[next]; next++; return h }
	alice, bob := user(t, 1), user(t, 2)
	restricted := openTmux(t, r, alice, tmuxOpen(1, "r1", ""))
	allowed := openTmux(t, r, alice, tmuxOpen(2, "r2", ""))
	tailscale := openTmux(t, r, bob, tmuxOpen(1, "r3", ""))
	jumped := openTmux(t, r, bob, tmuxOpen(2, "r4", ""))

	var asked []client.Route
	closed := r.m.CloseRestrictedRoutes(func(rt client.Route) bool {
		asked = append(asked, rt)
		return rt.Peer == node || len(rt.Onward) > 0 && rt.Onward[0] == node.String()
	})
	if closed != 2 || len(asked) != 3 {
		t.Fatalf("closed %d, asked %+v", closed, asked)
	}
	live := map[string]bool{}
	for _, s := range r.m.AdminSessions() {
		live[s.ID] = true
	}
	if live[restricted.SessionID] || live[jumped.SessionID] || !live[allowed.SessionID] || !live[tailscale.SessionID] {
		t.Fatalf("live sessions %v", live)
	}
	for _, peer := range []struct {
		p  *protocoltest.Peer
		id string
	}{{alice, restricted.SessionID}, {bob, jumped.SessionID}} {
		var told string
		for _, ev := range peer.p.Events(protocol.TypeTerminalClosed) {
			told += string(ev.Payload)
		}
		if strings.Count(told, reasonTailnet) != 1 || !strings.Contains(told, peer.id) {
			t.Fatalf("owner was told %q", told)
		}
	}
	for _, i := range []int{0, 3} {
		h := r.host(t, i)
		eventually(t, "connection closed", func() bool { h.mu.Lock(); defer h.mu.Unlock(); return h.closed == 1 })
		if h.ranAny("kill-session") {
			t.Fatal("tmux was killed")
		}
	}
	for _, rows := range [][]PersistentRow{r.rows(t, 1), r.rows(t, 2)} {
		for _, row := range rows {
			gone := row.SessionID == restricted.SessionID || row.SessionID == jumped.SessionID
			if row.Connected == gone {
				t.Fatalf("row %s connected=%v", row.SessionID, row.Connected)
			}
		}
	}
	if r.m.CloseRestrictedRoutes(func(client.Route) bool { return false }) != 0 {
		t.Fatal("an allowed session was closed")
	}
}

// A session without a connection of its own reports no route; the rule
// decides it like an unknown address (fail closed in netpolicy).
func TestCloseRestrictedRoutesWithoutConnection(t *testing.T) {
	m := newManager(t, Config{}, &fakeShells{})
	p := user(t, 1)
	res := open(t, m, p, 1)
	var got []client.Route
	if n := m.CloseRestrictedRoutes(func(rt client.Route) bool { got = append(got, rt); return !rt.Peer.IsValid() }); n != 1 {
		t.Fatalf("closed %d", n)
	}
	if len(got) != 1 || got[0].Peer.IsValid() || len(m.AdminSessions()) != 0 || len(p.Events(protocol.TypeTerminalClosed)) != 1 {
		t.Fatalf("routes %+v, sessions %+v, session %s", got, m.AdminSessions(), res.SessionID)
	}
}
