package settings

import (
	"encoding/json/jsontext"
	"testing"

	"github.com/bifrost0x/webssh/internal/principal/principaltest"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
	"github.com/bifrost0x/webssh/internal/realtime/protocol/protocoltest"
)

func TestRealtimeRoutesAnswerTheStoredValue(t *testing.T) {
	s, _ := newService(t, Environment{})
	routes := map[string]protocol.Route{}
	for _, r := range s.Routes() {
		if !r.Spec.Mutates {
			t.Errorf("%s does not re-check the session", r.Type)
		}
		routes[r.Type] = r
	}
	peer := protocoltest.NewPeer(t, principaltest.User(9))
	ctx := t.Context()
	cases := []struct {
		typ, payload, want string
	}{
		{protocol.TypeSettingsTheme, `{"theme":"noir"}`, `{"theme":"noir"}`},
		{protocol.TypeSettingsConfirmClose, `{"enabled":true}`, `{"enabled":true}`},
		{protocol.TypeSettingsDisconnect, `{"action":"close"}`, `{"action":"close"}`},
	}
	for _, c := range cases {
		got, werr := protocoltest.Call(ctx, routes[c.typ], peer, rawJSON(c.payload))
		if werr != nil || string(got) != c.want {
			t.Errorf("%s: %s %v", c.typ, got, werr)
		}
	}
	u, _ := s.User(ctx, 9)
	if u.Theme != "noir" || !u.ConfirmSessionClose || u.DisconnectSessionAction != "close" {
		t.Errorf("not stored: %+v", u)
	}
	for _, c := range []struct{ typ, payload, code string }{
		{protocol.TypeSettingsTheme, `{"theme":"nope"}`, "invalid_value"},
		{protocol.TypeSettingsDisconnect, `{"action":"later"}`, "invalid_value"},
		{protocol.TypeSettingsConfirmClose, `{"enabled":"yes"}`, "invalid_request"},
		// Python requires a boolean; a missing or null value is refused.
		{protocol.TypeSettingsConfirmClose, `{}`, "invalid_value"},
		{protocol.TypeSettingsConfirmClose, `{"enabled":null}`, "invalid_value"},
		{protocol.TypeSettingsTheme, `{"theme":"noir","extra":1}`, "invalid_request"},
	} {
		if _, werr := protocoltest.Call(ctx, routes[c.typ], peer, rawJSON(c.payload)); werr == nil || string(werr.Code) != c.code {
			t.Errorf("%s %s: %v", c.typ, c.payload, werr)
		}
	}
	recovery := principaltest.User(9)
	recovery.Recovery = true
	if _, werr := protocoltest.Call(ctx, routes[protocol.TypeSettingsTheme], protocoltest.NewPeer(t, recovery), rawJSON(`{"theme":"glass"}`)); werr == nil || werr.Code != "forbidden" {
		t.Errorf("recovery session: %v", werr)
	}
	if u, _ := s.User(ctx, 9); u.Theme != "noir" {
		t.Error("a refused message changed the theme")
	}
}

func rawJSON(s string) jsontext.Value { return jsontext.Value(s) }
