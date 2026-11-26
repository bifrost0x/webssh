package hosts

import (
	"context"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"strings"
	"testing"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
)

// fakeVariants switches the gateway and grants Tailscale SSH for one host.
type fakeVariants struct {
	gatewayOn bool
	tsHost    string
	asked     []string
}

func (f *fakeVariants) GatewayEnabled(context.Context) error {
	if !f.gatewayOn {
		return fault.New(fault.Forbidden, "SSH gateway integration is disabled by the administrator")
	}
	return nil
}

func (f *fakeVariants) GatewaySelector(username string) error {
	if strings.HasPrefix(username, " ") || strings.HasSuffix(username, ":") {
		return fault.New(fault.InvalidValue, "Gateway user and target are required without surrounding whitespace")
	}
	return nil
}

func (f *fakeVariants) TailscaleAccess(_ context.Context, host string, port int, remote string) error {
	f.asked = append(f.asked, host)
	if host != f.tsHost || port != 22 || remote != "tsuser" {
		return fault.New(fault.Forbidden, "Tailscale SSH target is not allowed")
	}
	return nil
}

func TestSaveGatewayAndTailscaleHosts(t *testing.T) {
	s := seeded(t, Legacy{})
	f := &fakeVariants{tsHost: "node.ts.example"}
	s.Variants = f
	ctx := t.Context()
	base := protocol.HostsProfileSave{Name: v(`"n"`), Host: v(`"gw.example"`), Username: v(`"alice:prod"`), AuthType: v(`"password"`)}
	if _, err := s.SaveProfile(ctx, oracleUser, base); code(err) != fault.Forbidden {
		t.Fatalf("gateway off: %v", err)
	}
	f.gatewayOn = true
	saved, err := s.SaveProfile(ctx, oracleUser, base)
	if err != nil {
		t.Fatalf("gateway on: %v", err)
	}
	var p map[string]jsontext.Value
	if err := json.Unmarshal(saved, &p); err != nil || string(p["username"]) != `"alice:prod"` {
		t.Fatalf("saved %s", saved)
	}
	bad := base
	bad.Username = v(`"alice:"`)
	if _, err := s.SaveProfile(ctx, oracleUser, bad); code(err) != fault.InvalidValue {
		t.Fatalf("bad selector: %v", err)
	}
	both := base
	both.Username, both.AuthType = v(`"alice:"`), v(`"tailscale"`)
	if _, err := s.SaveProfile(ctx, oracleUser, both); err == nil || !strings.Contains(err.Error(), "Tailscale SSH target is not allowed") {
		// Tailscale access is checked first, as in the Python handler.
		t.Fatalf("selector with tailscale: %v", err)
	}

	ts := protocol.HostsProfileSave{Name: v(`"t"`), Host: v(`"node.ts.example"`), Username: v(`"tsuser"`), AuthType: v(`"tailscale"`)}
	saved, err = s.SaveProfile(ctx, oracleUser, ts)
	if err != nil {
		t.Fatalf("tailscale host: %v", err)
	}
	if err := json.Unmarshal(saved, &p); err != nil || string(p["tailscale_authorized"]) != "true" || string(p["key_id"]) != "null" {
		t.Fatalf("saved %s", saved)
	}
	denied := ts
	denied.Host = v(`"other.example"`)
	if _, err := s.SaveProfile(ctx, oracleUser, denied); code(err) != fault.Forbidden {
		t.Fatalf("denied tailscale: %v", err)
	}
	withJump := ts
	withJump.JumpHostID = v(`"2735737b-d93a-4e54-acd5-85b740b63526"`)
	if _, err := s.SaveProfile(ctx, oracleUser, withJump); code(err) != fault.ValidationError {
		t.Fatalf("tailscale with jump: %v", err)
	}
	withSOCKS := ts
	withSOCKS.SOCKSProxyID = v(`"ae5c7232-6f7d-4457-bfca-0cc84e323aeb"`)
	if _, err := s.SaveProfile(ctx, oracleUser, withSOCKS); code(err) != fault.ValidationError {
		t.Fatalf("tailscale with socks: %v", err)
	}

	list, err := s.Profiles(ctx, oracleUser)
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, raw := range list {
		var q map[string]jsontext.Value
		_ = json.Unmarshal(raw, &q)
		if string(q["auth_type"]) == `"tailscale"` {
			found++
			if string(q["tailscale_authorized"]) != "true" {
				t.Errorf("listed %s", raw)
			}
		}
	}
	if found != 1 {
		t.Fatalf("listed %d Tailscale hosts", found)
	}
	f.tsHost = "revoked.example"
	list, _ = s.Profiles(ctx, oracleUser)
	for _, raw := range list {
		if strings.Contains(string(raw), `"tailscale"`) && !strings.Contains(string(raw), `"tailscale_authorized":false`) {
			t.Errorf("after the policy changed: %s", raw)
		}
	}
}

func TestResolveGatewayAndTailscaleHosts(t *testing.T) {
	s := seeded(t, Legacy{Profiles: []jsontext.Value{
		v(`{"id":"ts","name":"T","host":"ts.example","username":"tsuser","auth_type":"tailscale"}`),
		v(`{"id":"ts-jump","name":"TJ","host":"ts.example","username":"tsuser","auth_type":"tailscale","jump_host_id":"2735737b-d93a-4e54-acd5-85b740b63526"}`),
		v(`{"id":"gw","name":"G","host":"gw.example","username":"a:b","auth_type":"password"}`),
	}})
	s.Variants = &fakeVariants{gatewayOn: true}
	ts, err := s.Resolve(t.Context(), oracleUser, "ts")
	if err != nil || !ts.Display.Tailscale || ts.Hop.User != "tsuser" || ts.Hop.Auth.Password != "" || ts.Hop.Auth.KeyID != "" {
		t.Fatalf("tailscale: %+v %v", ts, err)
	}
	if _, err := s.Resolve(t.Context(), oracleUser, "ts-jump"); code(err) != fault.ValidationError {
		t.Fatalf("tailscale with jump: %v", err)
	}
	gw, err := s.Resolve(t.Context(), oracleUser, "gw")
	if err != nil || gw.Hop.User != "a:b" || gw.Display.Tailscale {
		t.Fatalf("gateway: %+v %v", gw, err)
	}
}
