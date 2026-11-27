package terminal

import (
	"context"
	"strconv"
	"strings"
	"testing"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
	"github.com/bifrost0x/webssh/internal/ssh/client"
)

type fakeRoutes struct{}

func (fakeRoutes) JumpHost(_ context.Context, _ int64, id string) (client.Hop, error) {
	switch id {
	case "pw":
		return client.Hop{Host: "bastion.test", Port: 22, User: "j"}, nil
	case "key":
		return client.Hop{Host: "bastion.test", Port: 22, User: "j", Auth: client.Auth{KeyID: "k1"}}, nil
	}
	return client.Hop{}, fault.New(fault.NotFound, "")
}

func (fakeRoutes) SOCKSProxy(_ context.Context, _ int64, id string) (client.SOCKS, error) {
	switch id {
	case "login":
		return client.SOCKS{Host: "proxy.test", Port: 1080, Username: "pu"}, nil
	case "open":
		return client.SOCKS{Host: "proxy.test", Port: 1080}, nil
	}
	return client.SOCKS{}, fault.New(fault.NotFound, "")
}

type fakeSaved map[string]string

func (f fakeSaved) Password(_ context.Context, owner int64, resource string) (string, error) {
	if pw, ok := f[resource]; ok && owner == 1 {
		return pw, nil
	}
	return "", fault.New(fault.Code("credential_missing"), "")
}

func (f fakeSaved) TargetPassword(_ context.Context, p principal.Principal, credentialID, token string, host string, port int, user, jump, socks string) (string, error) {
	key := strings.Join([]string{"target", credentialID, token, host, strconv.Itoa(port), user, jump, socks}, ":")
	if pw, ok := f[key]; ok && p.UserID == 1 {
		return pw, nil
	}
	return "", fault.New(fault.CredentialTargetChanged, "")
}

// Jump hosts with password sign-in and SOCKS5 logins get the password of
// the attempt or the saved one, with the checks of handle_ssh_connect.
func TestRouteSecrets(t *testing.T) {
	m := newManager(t, Config{}, &fakeShells{})
	m.routes = fakeRoutes{}
	m.profiles = fakeProfiles{
		"p-jump":  {Owner: 1, Hop: client.Hop{Host: "t.test", Port: 22, User: "u"}, Jumps: []client.Hop{{Host: "bastion.test", Port: 22, User: "j"}}, Display: client.Display{JumpHostID: "pw"}},
		"p-socks": {Owner: 1, Hop: client.Hop{Host: "t.test", Port: 22, User: "u"}, Proxy: &client.SOCKS{Host: "proxy.test", Port: 1080, Username: "pu"}, Display: client.Display{SOCKSProxyID: "login"}},
	}
	typed := func(mod func(*protocol.OpenTarget)) protocol.OpenTarget {
		r := protocol.OpenTarget{Host: "t.test", Username: "u", AuthType: protocol.AuthPassword, Password: "tp"}
		mod(&r)
		return r
	}
	ctx := t.Context()
	cases := []struct {
		name  string
		req   protocol.OpenTarget
		saved bool
		check func(client.Target) bool
		err   string
	}{
		{name: "typed jump password", req: typed(func(r *protocol.OpenTarget) { r.JumpHostID, r.JumpPassword = "pw", "jp" }),
			check: func(t client.Target) bool {
				return t.Jumps[0].Auth == client.Auth{Password: "jp"} && t.Hop.Auth.Password == "tp"
			}},
		{name: "jump password missing", req: typed(func(r *protocol.OpenTarget) { r.JumpHostID = "pw" }), err: "Jump host password or SSH key required"},
		{name: "key jump ignores a password", req: typed(func(r *protocol.OpenTarget) { r.JumpHostID, r.JumpPassword = "key", "jp" }),
			check: func(t client.Target) bool { return t.Jumps[0].Auth == client.Auth{KeyID: "k1"} }},
		{name: "saved jump password", saved: true, req: typed(func(r *protocol.OpenTarget) { r.JumpHostID, r.JumpSavedPassword = "pw", true }),
			check: func(t client.Target) bool { return t.Jumps[0].Auth.Password == "saved-jump" }},
		{name: "saved passwords not wired", req: typed(func(r *protocol.OpenTarget) { r.JumpHostID, r.JumpSavedPassword = "pw", true }), err: string(fault.NotAvailableInPreview)},
		{name: "typed socks login", req: typed(func(r *protocol.OpenTarget) { r.SOCKSProxyID, r.SOCKSPassword = "login", "sp" }),
			check: func(t client.Target) bool {
				return *t.Proxy == client.SOCKS{Host: "proxy.test", Port: 1080, Username: "pu", Password: "sp"} && t.Proxy.Guard == nil
			}},
		{name: "socks password missing", req: typed(func(r *protocol.OpenTarget) { r.SOCKSProxyID = "login" }), err: "SOCKS5 proxy password required"},
		{name: "socks password too long", req: typed(func(r *protocol.OpenTarget) { r.SOCKSProxyID, r.SOCKSPassword = "login", strings.Repeat("ä", 128) }),
			err: "SOCKS5 proxy password must contain 1 to 255 UTF-8 bytes"},
		{name: "socks typed and saved", saved: true, req: typed(func(r *protocol.OpenTarget) {
			r.SOCKSProxyID, r.SOCKSPassword, r.SOCKSSavedPassword = "login", "sp", true
		}), err: string(fault.InvalidRequest)},
		{name: "saved socks password", saved: true, req: typed(func(r *protocol.OpenTarget) { r.SOCKSProxyID, r.SOCKSSavedPassword = "login", true }),
			check: func(t client.Target) bool { return t.Proxy.Password == "saved-socks" && t.Proxy.Guard != nil }},
		{name: "open proxy ignores a password", req: typed(func(r *protocol.OpenTarget) { r.SOCKSProxyID, r.SOCKSPassword = "open", "sp" }),
			check: func(t client.Target) bool { return t.Proxy.Password == "" && t.Proxy.Username == "" }},
		{name: "profile with jump password", req: protocol.OpenTarget{ProfileID: "p-jump", AuthType: protocol.AuthPassword, Password: "tp", JumpPassword: "jp"},
			check: func(t client.Target) bool { return t.Jumps[0].Auth.Password == "jp" && t.Hop.Auth.Password == "tp" }},
		{name: "profile with saved passwords", saved: true, req: protocol.OpenTarget{ProfileID: "p-socks", AuthType: protocol.AuthPassword, SavedPassword: true, SOCKSSavedPassword: true},
			check: func(t client.Target) bool {
				return t.Hop.Auth.Password == "saved-host" && t.Proxy.Password == "saved-socks"
			}},
		{name: "profile socks password missing", req: protocol.OpenTarget{ProfileID: "p-socks", AuthType: protocol.AuthPassword, Password: "tp"}, err: "SOCKS5 proxy password required"},
		{name: "typed and saved target password", saved: true, req: typed(func(r *protocol.OpenTarget) { r.SavedPassword = true }), err: string(fault.InvalidRequest)},
		{name: "saved target password", saved: true, req: typed(func(r *protocol.OpenTarget) {
			r.Password, r.SavedPassword, r.CredentialID, r.CredentialTargetToken = "", true, "c1", "tok"
		}), check: func(t client.Target) bool { return t.Hop.Auth.Password == "saved-target" && t.Hop.Auth.Guard != nil }},
		{name: "saved target password for another target", saved: true, req: typed(func(r *protocol.OpenTarget) {
			r.Password, r.SavedPassword, r.CredentialID, r.CredentialTargetToken, r.Port = "", true, "c1", "tok", 2222
		}), err: string(fault.CredentialTargetChanged)},
		{name: "saved target password without credential", saved: true, req: typed(func(r *protocol.OpenTarget) {
			r.Password, r.SavedPassword = "", true
		}), err: string(fault.InvalidRequest)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m.saved = nil
			if tc.saved {
				m.saved = fakeSaved{"jump:pw": "saved-jump", "socks:login": "saved-socks", "p-socks": "saved-host",
					"target:c1:tok:t.test:22:u::": "saved-target"}
			}
			got, err := m.resolve(principal.With(ctx, principal.Principal{UserID: 1, SessionID: "s"}), 1, tc.req)
			if tc.err != "" {
				if err == nil || !strings.Contains(err.Error(), tc.err) && string(fault.CodeOf(err)) != tc.err {
					t.Fatalf("got %+v, %v; want %s", got, err, tc.err)
				}
				return
			}
			if err != nil || !tc.check(got) {
				t.Fatalf("got %+v, %v", got, err)
			}
		})
	}
	// The resolver's own target is never changed in place.
	if p := m.profiles.(fakeProfiles)["p-jump"]; p.Jumps[0].Auth.Password != "" {
		t.Fatal("the profile's jump hop was modified")
	}
}

// A saved password is resolved again right before it is sent; one that
// changed meanwhile cancels the attempt.
func TestSavedPasswordGuard(t *testing.T) {
	m := newManager(t, Config{}, &fakeShells{})
	m.profiles = fakeProfiles{"p": {Owner: 1, Hop: client.Hop{Host: "t.test", Port: 22, User: "u"}}}
	saved := fakeSaved{"p": "one"}
	m.saved = saved
	ctx := principal.With(t.Context(), principal.Principal{UserID: 1, SessionID: "s"})
	got, err := m.resolve(ctx, 1, protocol.OpenTarget{ProfileID: "p", AuthType: protocol.AuthPassword, SavedPassword: true})
	if err != nil || got.Hop.Auth.Guard == nil {
		t.Fatalf("%+v %v", got, err)
	}
	if err := got.Hop.Auth.Guard.Check(ctx); err != nil {
		t.Fatalf("unchanged password refused: %v", err)
	}
	saved["p"] = "two"
	if err := got.Hop.Auth.Guard.Check(ctx); fault.CodeOf(err) != fault.CredentialTargetChanged {
		t.Fatalf("changed password: %v", err)
	}
	delete(saved, "p")
	if err := got.Hop.Auth.Guard.Check(ctx); fault.CodeOf(err) != fault.Code("credential_missing") {
		t.Fatalf("removed assignment: %v", err)
	}
}

// A saved SOCKS5 password is guarded like the other saved passwords: a
// changed or removed assignment refuses it before the login is sent.
func TestSavedSOCKSPasswordGuard(t *testing.T) {
	m := newManager(t, Config{}, &fakeShells{})
	m.profiles = fakeProfiles{"p": {Owner: 1, Hop: client.Hop{Host: "t.test", Port: 22, User: "u"},
		Proxy: &client.SOCKS{Host: "proxy.test", Port: 1080, Username: "pu"}, Display: client.Display{SOCKSProxyID: "login"}}}
	saved := fakeSaved{"socks:login": "one"}
	m.saved = saved
	ctx := principal.With(t.Context(), principal.Principal{UserID: 1, SessionID: "s"})
	got, err := m.resolve(ctx, 1, protocol.OpenTarget{ProfileID: "p", AuthType: protocol.AuthPassword, Password: "tp", SOCKSSavedPassword: true})
	if err != nil || got.Proxy.Guard == nil {
		t.Fatalf("%+v %v", got, err)
	}
	if err := got.Proxy.Guard.Check(ctx); err != nil {
		t.Fatalf("unchanged password refused: %v", err)
	}
	saved["socks:login"] = "two"
	if err := got.Proxy.Guard.Check(ctx); fault.CodeOf(err) != fault.CredentialTargetChanged {
		t.Fatalf("changed password: %v", err)
	}
	delete(saved, "socks:login")
	if err := got.Proxy.Guard.Check(ctx); err == nil {
		t.Fatal("removed assignment accepted")
	}
}
