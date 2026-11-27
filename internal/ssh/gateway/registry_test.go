package gateway

import (
	"context"
	json "encoding/json/v2"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal/principaltest"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
	"github.com/bifrost0x/webssh/internal/realtime/protocol/protocoltest"
)

func route(t *testing.T, r *Registry, typ string) protocol.Route {
	t.Helper()
	for _, rt := range r.Routes() {
		if rt.Type == typ {
			return rt
		}
	}
	t.Fatalf("no route %s", typ)
	return protocol.Route{}
}

// TestRoutesReachOnlyTheOwnAttempt drives a pending challenge through the
// realtime routes: another connection of the same user, another user and a
// wrong prompt id all see a missing prompt; the owner answers once.
func TestRoutesReachOnlyTheOwnAttempt(t *testing.T) {
	r := &Registry{}
	alice := principaltest.User(7)
	peer := protocoltest.NewPeer(t, alice)
	sameUser := protocoltest.NewPeer(t, alice)
	mallory := protocoltest.NewPeer(t, principaltest.User(8))
	a, actx, end, err := r.Begin(t.Context(), Owner{Peer: peer.ID(), UserID: 7}, "req-1", peer, true)
	if err != nil {
		t.Fatal(err)
	}
	defer end()
	answers := make(chan []string, 1)
	go func() {
		got, err := a.Challenge(actx, "target", "Warpgate", "", []Prompt{{Label: "OTP: "}})
		if err != nil {
			t.Error(err)
		}
		answers <- got
	}()
	var shown protocol.PromptInteractive
	for {
		if ev := peer.Events(protocol.TypePromptInteractive); len(ev) > 0 {
			if err := json.Unmarshal(ev[0].Payload, &shown); err != nil {
				t.Fatal(err)
			}
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	respond := route(t, r, protocol.TypePromptRespond)
	call := func(p *protocoltest.Peer, req protocol.PromptRespond) *protocol.Error {
		_, perr := protocoltest.Call(t.Context(), respond, p, req)
		return perr
	}
	good := protocol.PromptRespond{RequestID: "req-1", PromptID: shown.PromptID, Answers: []string{"424242"}}
	// Another id of the same length; the first character differs from the
	// shown one whatever it is.
	other := "x"
	if shown.PromptID[0] == 'x' {
		other = "y"
	}
	other += shown.PromptID[1:]
	for name, tc := range map[string]struct {
		p   *protocoltest.Peer
		req protocol.PromptRespond
	}{
		"other connection": {sameUser, good},
		"other user":       {mallory, good},
		"wrong prompt":     {peer, protocol.PromptRespond{RequestID: "req-1", PromptID: other, Answers: []string{"1"}}},
		"wrong request":    {peer, protocol.PromptRespond{RequestID: "req-2", PromptID: shown.PromptID, Answers: []string{"1"}}},
		"wrong count":      {peer, protocol.PromptRespond{RequestID: "req-1", PromptID: shown.PromptID, Answers: []string{"1", "2"}}},
	} {
		if perr := call(tc.p, tc.req); perr == nil || perr.Code != fault.NotFound {
			t.Errorf("%s: %+v", name, perr)
		}
	}
	if perr := call(peer, protocol.PromptRespond{RequestID: "req-1", PromptID: shown.PromptID, Answers: []string{strings.Repeat("x", MaxAnswerBytes+1)}}); perr == nil {
		t.Error("oversized answer accepted")
	}
	if perr := call(peer, good); perr != nil {
		t.Fatalf("owner: %+v", perr)
	}
	if perr := call(peer, good); perr == nil {
		t.Error("replay accepted")
	}
	if got := <-answers; len(got) != 1 || got[0] != "424242" {
		t.Fatalf("answers %v", got)
	}

	input := route(t, r, protocol.TypeGatewayInput)
	if _, perr := protocoltest.Call(t.Context(), input, peer, protocol.GatewayInput{RequestID: "req-1", Data: "y"}); perr == nil {
		t.Error("input during authentication accepted")
	}
	if err := a.StartSetup(); err != nil {
		t.Fatal(err)
	}
	if _, perr := protocoltest.Call(t.Context(), input, mallory, protocol.GatewayInput{RequestID: "req-1", Data: "y"}); perr == nil {
		t.Error("foreign input accepted")
	}
	if _, perr := protocoltest.Call(t.Context(), input, peer, protocol.GatewayInput{RequestID: "req-1", Data: "y"}); perr != nil {
		t.Errorf("input: %+v", perr)
	}
	if err := a.Output(t.Context(), []byte("ok")); err != nil {
		t.Fatal(err)
	}
	ack := route(t, r, protocol.TypeGatewayAck)
	if _, perr := protocoltest.Call(t.Context(), ack, peer, protocol.GatewayAck{RequestID: "req-1", Sequence: 2}); perr == nil {
		t.Error("unknown sequence acknowledged")
	}
	if _, perr := protocoltest.Call(t.Context(), ack, peer, protocol.GatewayAck{RequestID: "req-1", Sequence: 1}); perr != nil {
		t.Errorf("ack: %+v", perr)
	}
}

func TestBeginRefusesDuplicatesAndBoundsTheRegistry(t *testing.T) {
	r := &Registry{Max: 2}
	ev := newEvents()
	_, _, end1, err := r.Begin(t.Context(), owner, "a", ev, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := r.Begin(t.Context(), owner, "a", ev, false); fault.CodeOf(err) != fault.Busy {
		t.Fatalf("duplicate: %v", err)
	}
	_, _, end2, err := r.Begin(t.Context(), owner, "b", ev, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := r.Begin(t.Context(), owner, "c", ev, false); fault.CodeOf(err) != fault.Busy {
		t.Fatalf("over the limit: %v", err)
	}
	end1()
	end1() // idempotent
	end2()
	if r.Pending() != 0 {
		t.Fatalf("%d attempts left", r.Pending())
	}
}

func TestAttemptContextEnds(t *testing.T) {
	r := &Registry{}
	_, actx, end, err := r.Begin(t.Context(), owner, "a", newEvents(), false)
	if err != nil {
		t.Fatal(err)
	}
	if d, ok := actx.Deadline(); !ok || time.Until(d) > AttemptTimeout {
		t.Fatalf("attempt deadline %v %v", d, ok)
	}
	end()
	if !errors.Is(actx.Err(), context.Canceled) {
		t.Fatalf("after end: %v", actx.Err())
	}
}

func TestDisableSparesOrdinaryAttempts(t *testing.T) {
	r := &Registry{}
	_, gctx, gend, _ := r.Begin(t.Context(), owner, "gw", newEvents(), true)
	_, octx, oend, _ := r.Begin(t.Context(), owner, "plain", newEvents(), false)
	defer gend()
	defer oend()
	r.Disable()
	if !errors.Is(context.Cause(gctx), ErrDisabled) {
		t.Fatalf("gateway attempt: %v", context.Cause(gctx))
	}
	if octx.Err() != nil {
		t.Fatal("ordinary attempt cancelled by the gateway switch")
	}
}

func FuzzParseSelector(f *testing.F) {
	for _, s := range []string{"alice:prod", "a:b:c", " u:t", "ticket-x:y", "u:\u2028", "\xff:t"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		user, target, err := ParseSelector(s)
		if err != nil {
			return
		}
		if user+":"+target != s || len(s) > MaxSelectorBytes || strings.Contains(user, ":") ||
			strings.TrimSpace(user) != user || strings.TrimSpace(target) != target {
			t.Fatalf("%q -> %q %q", s, user, target)
		}
	})
}

func FuzzDecode(f *testing.F) {
	f.Add([]byte("ab€"), 2)
	f.Add([]byte{0xff, 0xe2, 0x82}, 1)
	f.Fuzz(func(t *testing.T, data []byte, cut int) {
		if len(data) == 0 {
			return
		}
		cut = (cut%len(data) + len(data)) % len(data)
		a := testAttempt(nil)
		got := a.decode(data[:cut]) + a.decode(data[cut:])
		want := validText(string(data))
		if len(a.carry) == 0 && got != want {
			t.Fatalf("%q split at %d: %q, want %q", data, cut, got, want)
		}
	})
}
