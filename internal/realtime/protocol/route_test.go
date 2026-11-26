package protocol_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/principal/principaltest"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
	"github.com/bifrost0x/webssh/internal/realtime/protocol/protocoltest"
)

func TestHandle(t *testing.T) {
	t.Parallel()
	var seen principal.Principal
	route := protocol.Handle(protocol.TypeTerminalResize, protocol.Spec{},
		func(ctx context.Context, peer protocol.Peer, req protocol.TerminalResize) (protocol.TerminalResize, error) {
			p, err := principal.Require(ctx)
			if err != nil {
				return protocol.TerminalResize{}, err
			}
			seen = p
			return req, nil
		})
	peer := protocoltest.NewPeer(t, principaltest.User(5))

	got, werr := protocoltest.Call(t.Context(), route, peer, map[string]int{"ch": 2, "cols": 5000})
	if werr != nil {
		t.Fatalf("call failed: %+v", werr)
	}
	if want := `{"ch":2,"cols":1000,"rows":24}`; string(got) != want {
		t.Fatalf("result %s, want %s (Validate must clamp)", got, want)
	}
	if seen.UserID != 5 {
		t.Fatalf("handler context carried %+v", seen)
	}

	tests := []struct {
		name    string
		payload any
		want    fault.Code
	}{
		{name: "unknown member", payload: map[string]int{"ch": 1, "x": 1}, want: fault.InvalidRequest},
		{name: "differently cased member", payload: map[string]int{"Ch": 1}, want: fault.InvalidRequest},
		{name: "validation", payload: map[string]int{"ch": 0}, want: fault.InvalidRequest},
		{name: "too large", payload: map[string]string{"pad": strings.Repeat("x", protocol.DefaultMaxPayload)}, want: fault.TooLarge},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, werr := protocoltest.Call(t.Context(), route, peer, tt.payload)
			if werr == nil || werr.Code != tt.want {
				t.Fatalf("got %+v, want code %q", werr, tt.want)
			}
		})
	}
}

func TestWireError(t *testing.T) {
	t.Parallel()
	if protocol.WireError(nil) != nil {
		t.Fatal("nil error produced a wire error")
	}
	internal := protocol.WireError(errors.New("dial tcp 10.0.0.1:22: secret detail"))
	if internal.Code != fault.Internal || strings.Contains(internal.Message, "secret") {
		t.Fatalf("unclassified error leaked: %+v", internal)
	}
	limited := protocol.WireError(&fault.Error{Code: fault.RateLimited, RetryAfter: 1500 * time.Microsecond})
	if limited.Code != fault.RateLimited || limited.RetryAfterMS != 1 {
		t.Fatalf("rate limit: %+v", limited)
	}
	details := map[string]any{"usages": []string{"web-01"}}
	inUse := protocol.WireError(fmt.Errorf("delete: %w", &fault.Error{Code: fault.Conflict, Details: details}))
	if inUse.Code != fault.Conflict || inUse.Details["usages"] == nil {
		t.Fatalf("details lost: %+v", inUse)
	}
	if hidden := protocol.WireError(&fault.Error{Code: "made_up", Details: details}); hidden.Details != nil {
		t.Fatalf("details of an unknown code were sent: %+v", hidden)
	}
}

func TestPeerDouble(t *testing.T) {
	t.Parallel()
	peer := protocoltest.NewPeer(t, principaltest.User(1))
	if err := peer.SendEvent(protocol.TypeTerminalClosed, protocol.TerminalClosed{SessionID: "s", Reason: "closed"}); err != nil {
		t.Fatal(err)
	}
	peer.Close()
	if err := peer.SendEvent(protocol.TypeTerminalClosed, protocol.TerminalClosed{}); !errors.Is(err, protocoltest.ErrClosed) {
		t.Fatalf("send after close: %v", err)
	}
	if peer.Context().Err() == nil {
		t.Fatal("context not cancelled by Close")
	}
	events := peer.Events(protocol.TypeTerminalClosed)
	if len(events) != 1 || string(events[0].Payload) != `{"session_id":"s","reason":"closed"}` {
		t.Fatalf("events %+v", events)
	}
}

func TestCatalog(t *testing.T) {
	t.Parallel()
	seen := map[string]bool{}
	for _, m := range protocol.V1() {
		if seen[m.Name] || !protocol.ValidType(m.Name) || m.Name == protocol.TypeResult {
			t.Errorf("catalog entry %q is duplicate, invalid or reserved", m.Name)
		}
		seen[m.Name] = true
		if m.Dir != protocol.ClientRequest && m.Dir != protocol.ServerEvent {
			t.Errorf("%s: direction %q", m.Name, m.Dir)
		}
		if !strings.HasPrefix(m.Owner, "internal/") {
			t.Errorf("%s: owner %q", m.Name, m.Owner)
		}
		if got, ok := protocol.Lookup(m.Name); !ok || got != m {
			t.Errorf("Lookup(%q) = %+v, %v", m.Name, got, ok)
		}
	}
	if _, ok := protocol.Lookup("terminal.unknown"); ok {
		t.Error("Lookup found an unknown type")
	}
}

func TestPayloadValidation(t *testing.T) {
	t.Parallel()
	good := protocol.TerminalOpen{Ch: 1, RequestID: "r-1", Target: protocol.OpenTarget{Host: "h", AuthType: protocol.AuthKey}}
	if err := good.Validate(); err != nil || good.Rows != 24 || good.Cols != 80 {
		t.Fatalf("valid open rejected or not defaulted: %v %+v", err, good)
	}
	tmux := protocol.TerminalOpen{Ch: 1, RequestID: "r-2", ReplacementOf: "s-1", Target: protocol.OpenTarget{Host: "h", AuthType: protocol.AuthKey, UseTmux: true, TmuxSessionName: "webssh-1"}}
	if err := tmux.Validate(); err != nil {
		t.Fatalf("tmux open rejected: %v", err)
	}
	bad := []protocol.TerminalOpen{
		{Ch: 0, RequestID: "r", Target: protocol.OpenTarget{Host: "h", AuthType: protocol.AuthKey}},
		{Ch: 1, RequestID: "", Target: protocol.OpenTarget{Host: "h", AuthType: protocol.AuthKey}},
		{Ch: 1, RequestID: "r", Target: protocol.OpenTarget{Host: "h", AuthType: "agent"}},
		{Ch: 1, RequestID: "r", Target: protocol.OpenTarget{AuthType: protocol.AuthPassword}},
		{Ch: 1, RequestID: "r", Target: protocol.OpenTarget{Host: "h", Port: 70000, AuthType: protocol.AuthPassword}},
		{Ch: 1 << 31, RequestID: "r", Target: protocol.OpenTarget{Host: "h", AuthType: protocol.AuthPassword}},
		{Ch: 1, RequestID: "r", Target: protocol.OpenTarget{Host: "h", AuthType: protocol.AuthKey, TmuxSessionName: strings.Repeat("t", protocol.MaxTmuxSessionName+1)}},
		{Ch: 1, RequestID: "r", ReplacementOf: "a b", Target: protocol.OpenTarget{Host: "h", AuthType: protocol.AuthKey}},
	}
	for i, r := range bad {
		if err := r.Validate(); err == nil {
			t.Errorf("case %d accepted: %+v", i, r)
		}
	}
	answer := protocol.PromptAnswer{PromptID: "p", Kind: "other"}
	if answer.Validate() == nil {
		t.Error("unknown prompt kind accepted")
	}
	note := protocol.NotesSave{Text: strings.Repeat("ü", protocol.MaxNoteRunes)}
	if note.Validate() != nil {
		t.Error("note at the limit rejected; the limit counts characters, not bytes")
	}
	note.Text += "x"
	if note.Validate() == nil {
		t.Error("note over the limit accepted")
	}
}
