//go:build e2e

package terminal

import (
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
)

func TestFixtureSessions(t *testing.T) {
	m := newLimited(t, 2, 1, Config{}, &fakeShells{})
	peer := user(t, 1)
	real := open(t, m, peer, 1)
	ids, err := m.ReplaceFixtureSessions(t.Context(), peer, 1, 3)
	if err != nil || len(ids) != 3 {
		t.Fatalf("fixtures: %v %v", ids, err)
	}
	list, _ := m.Restorable(t.Context(), principal.Principal{UserID: 1})
	if len(list) != 4 {
		t.Fatalf("%d restorable, want the real one and three fixtures", len(list))
	}
	var att protocol.TerminalAttached
	if werr := call(t, m, peer, protocol.TypeTerminalAttach, protocol.TerminalAttach{Ch: 5, SessionID: ids[0]}, &att); werr != nil {
		t.Fatal(werr)
	}
	if output(t, peer, 5) != fixtureOutput || att.Seq != 1 {
		t.Fatalf("fixture replay %q, seq %d", output(t, peer, 5), att.Seq)
	}
	again, err := m.ReplaceFixtureSessions(t.Context(), peer, 1, 0)
	if err != nil || len(again) != 0 {
		t.Fatal(err)
	}
	if list, _ := m.Restorable(t.Context(), principal.Principal{UserID: 1}); len(list) != 1 || list[0].SessionID != real.SessionID {
		t.Fatalf("replace touched a real session: %+v", list)
	}
	if _, err := m.ReplaceFixtureSessions(t.Context(), peer, 1, 13); err == nil {
		t.Fatal("more than 12 fixtures")
	}
}

// The output load runs through the real ledger: frames wait for acks and
// count as in flight.
func TestEmit(t *testing.T) {
	m := newManager(t, Config{Flow: FlowLimits{StreamFrames: 2}}, &fakeShells{})
	peer := user(t, 1)
	for seq := uint64(1); seq <= 2; seq++ {
		if err := m.Emit(t.Context(), peer, "load-0", seq, []byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	bind := peer.Events(TypeOutputStream)
	if len(bind) != 1 {
		t.Fatalf("%d stream bindings", len(bind))
	}
	st := decode[OutputStream](t, bind[0])
	if st.SessionID != "load-0" || st.Ch < fixtureChannelBase || m.InFlight(peer) != 2 {
		t.Fatalf("binding %+v, in flight %d", st, m.InFlight(peer))
	}
	done := make(chan error, 1)
	go func() { done <- m.Emit(t.Context(), peer, "load-0", 3, []byte("x")) }()
	select {
	case <-done:
		t.Fatal("frame sent without credit")
	case <-time.After(30 * time.Millisecond):
	}
	if err := m.HandleBinary(peer, ack(st.Ch, 2)); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil || m.InFlight(peer) != 1 {
		t.Fatalf("after ack: %v, in flight %d", err, m.InFlight(peer))
	}
	// Input on a synthetic stream goes nowhere.
	if err := m.HandleBinary(peer, input(st.Ch, 1, "x", false)); err != nil {
		t.Fatal(err)
	}
	m.PeerClosed(peer)
	if m.InFlight(peer) != 0 {
		t.Fatal("closed connection keeps credit")
	}
}
