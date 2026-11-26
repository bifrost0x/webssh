package terminal

import (
	"context"
	"log/slog"
	"sync"
	"testing"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
	"github.com/bifrost0x/webssh/internal/ssh/client"
)

type fakeVariants struct {
	mu       sync.Mutex
	attempts []VariantAttempt
	ended    int
	refuse   error
}

type variantCtxKey struct{}

// fakeChallenger answers every round with one fixed answer per question.
type fakeChallenger struct{ asked []client.Challenge }

func (c *fakeChallenger) Challenge(_ context.Context, q client.Challenge) ([]string, error) {
	c.asked = append(c.asked, q)
	out := make([]string, len(q.Questions))
	for i := range out {
		out[i] = "123456"
	}
	return out, nil
}

func (f *fakeVariants) Interact(ctx context.Context, a VariantAttempt) (client.Challenger, context.Context, func(), error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.attempts = append(f.attempts, a)
	if f.refuse != nil {
		return nil, nil, nil, f.refuse
	}
	return &fakeChallenger{}, context.WithValue(ctx, variantCtxKey{}, "interact"), func() {
		f.mu.Lock()
		f.ended++
		f.mu.Unlock()
	}, nil
}

func (f *fakeVariants) Prepare(ctx context.Context, a VariantAttempt) (client.Target, context.Context, func(), error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.attempts = append(f.attempts, a)
	if f.refuse != nil {
		return client.Target{}, nil, nil, f.refuse
	}
	t := a.Target
	t.Variant = &client.Variant{}
	return t, context.WithValue(ctx, variantCtxKey{}, "variant"), func() {
		f.mu.Lock()
		f.ended++
		f.mu.Unlock()
	}, nil
}

func variantManager(t *testing.T, shells *fakeShells, v Variants, profiles Profiles) *Manager {
	t.Helper()
	m, err := New(Config{}, Deps{Shells: shells, Log: slog.New(slog.DiscardHandler), Variants: v, Profiles: profiles, Quotas: testQuotas(t, 10, 5)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Shutdown(context.Background()) })
	return m
}

func TestGatewaySelectorUsesTheVariant(t *testing.T) {
	var seenCtx any
	shells := &fakeShells{before: func(ctx context.Context, _ client.Interaction) error {
		seenCtx = ctx.Value(variantCtxKey{})
		return nil
	}}
	v := &fakeVariants{}
	m := variantManager(t, shells, v, nil)
	peer := user(t, 1)
	req := openReq(1, "gw1")
	req.Target.Username, req.Target.Password, req.Target.Interactive = "alice:prod", "", true
	var res protocol.TerminalOpened
	if werr := call(t, m, peer, protocol.TypeTerminalOpen, req, &res); werr != nil {
		t.Fatalf("open: %+v", werr)
	}
	if len(v.attempts) != 1 || !v.attempts[0].Interactive || v.attempts[0].RequestID != "gw1" ||
		v.attempts[0].Peer.ID() != peer.ID() || v.attempts[0].User.UserID != 1 ||
		v.attempts[0].Target.Hop.User != "alice:prod" || v.attempts[0].Target.Hop.Auth.Password != "" {
		t.Fatalf("attempts %+v", v.attempts)
	}
	if shells.targets[0].Variant == nil || seenCtx != "variant" {
		t.Fatal("the shell was not opened with the variant and its context")
	}
	if v.ended != 1 {
		t.Fatalf("end called %d times", v.ended)
	}
	if res.Info.Username != "alice:prod" || res.Info.AuthType != protocol.AuthPassword {
		t.Fatalf("info %+v", res.Info)
	}
}

func TestTailscaleTargetUsesTheVariant(t *testing.T) {
	v := &fakeVariants{}
	m := variantManager(t, &fakeShells{}, v, nil)
	peer := user(t, 1)
	req := openReq(1, "ts1")
	req.Target.AuthType, req.Target.Password, req.Target.Username = protocol.AuthTailscale, "", "tsuser"
	var res protocol.TerminalOpened
	if werr := call(t, m, peer, protocol.TypeTerminalOpen, req, &res); werr != nil {
		t.Fatalf("open: %+v", werr)
	}
	if len(v.attempts) != 1 || !v.attempts[0].Target.Display.Tailscale || res.Info.AuthType != protocol.AuthTailscale {
		t.Fatalf("attempts %+v, info %+v", v.attempts, res.Info)
	}
}

func TestVariantRefusals(t *testing.T) {
	v := &fakeVariants{}
	m := variantManager(t, &fakeShells{}, v, nil)
	peer := user(t, 1)
	mod := func(f func(*protocol.OpenTarget)) protocol.TerminalOpen {
		r := openReq(1, "r")
		f(&r.Target)
		return r
	}
	for name, tc := range map[string]struct {
		req  protocol.TerminalOpen
		code fault.Code
	}{
		"tailscale with jump":    {mod(func(o *protocol.OpenTarget) { o.AuthType = "tailscale"; o.JumpHostID = "j1" }), fault.InvalidValue},
		"tailscale with socks":   {mod(func(o *protocol.OpenTarget) { o.AuthType = "tailscale"; o.SOCKSProxyID = "s1" }), fault.InvalidValue},
		"tailscale and selector": {mod(func(o *protocol.OpenTarget) { o.AuthType = "tailscale"; o.Username = "a:b" }), fault.InvalidValue},
		"tailscale bad user":     {mod(func(o *protocol.OpenTarget) { o.AuthType = "tailscale"; o.Username = "a b" }), fault.InvalidValue},
		"gateway without key":    {mod(func(o *protocol.OpenTarget) { o.AuthType = "key"; o.Username = "a:b" }), fault.InvalidValue},
	} {
		if werr := call(t, m, peer, protocol.TypeTerminalOpen, tc.req, nil); werr == nil || werr.Code != tc.code {
			t.Errorf("%s: %+v, want %s", name, werr, tc.code)
		}
	}
	if len(v.attempts) != 0 {
		t.Fatalf("refused targets reached the provider: %+v", v.attempts)
	}
	v.refuse = fault.New(fault.Forbidden, "SSH gateway integration is disabled by the administrator")
	req := openReq(2, "r2")
	req.Target.Username = "a:b"
	if werr := call(t, m, peer, protocol.TypeTerminalOpen, req, nil); werr == nil || werr.Code != fault.Forbidden ||
		werr.Message != "SSH gateway integration is disabled by the administrator" {
		t.Fatalf("provider refusal: %+v", werr)
	}
}

func TestSavedTailscaleHostUsesTheVariant(t *testing.T) {
	v := &fakeVariants{}
	profiles := fakeProfiles{"p1": {Owner: 1, Hop: client.Hop{Host: "node", Port: 22, User: "tsuser"},
		Display: client.Display{Tailscale: true}}}
	m := variantManager(t, &fakeShells{}, v, profiles)
	req := protocol.TerminalOpen{Ch: 1, RequestID: "p", Rows: 24, Cols: 80, Target: protocol.OpenTarget{ProfileID: "p1", AuthType: "password"}}
	var res protocol.TerminalOpened
	if werr := call(t, m, user(t, 1), protocol.TypeTerminalOpen, req, &res); werr != nil {
		t.Fatalf("open: %+v", werr)
	}
	if len(v.attempts) != 1 || res.Info.AuthType != protocol.AuthTailscale || res.Info.ProfileID != "p1" {
		t.Fatalf("attempts %+v info %+v", v.attempts, res.Info)
	}
}

// An ordinary connection whose page answers prompts gets the provider's
// challenger on its interaction, so the dialer can put keyboard-interactive
// rounds to the user (C-CONN-09); without the flag it gets none.
func TestInteractiveTargetGetsTheChallenger(t *testing.T) {
	var challenger client.Challenger
	var seenCtx any
	shells := &fakeShells{before: func(ctx context.Context, ix client.Interaction) error {
		challenger, _ = ix.(client.Challenger)
		seenCtx = ctx.Value(variantCtxKey{})
		return nil
	}}
	v := &fakeVariants{}
	m := variantManager(t, shells, v, nil)
	peer := user(t, 1)
	req := openReq(1, "ki1")
	req.Target.Interactive = true
	if werr := call(t, m, peer, protocol.TypeTerminalOpen, req, nil); werr != nil {
		t.Fatalf("open: %+v", werr)
	}
	if challenger == nil || seenCtx != "interact" || len(v.attempts) != 1 || v.attempts[0].RequestID != "ki1" || v.ended != 1 {
		t.Fatalf("challenger %v ctx %v attempts %+v ended %d", challenger, seenCtx, v.attempts, v.ended)
	}
	if shells.targets[0].Variant != nil {
		t.Fatal("an ordinary connection got a variant")
	}
	answers, err := challenger.Challenge(t.Context(), client.Challenge{Questions: []client.Question{{Text: "Code:"}}})
	if err != nil || len(answers) != 1 {
		t.Fatalf("challenge: %v %v", answers, err)
	}

	challenger = nil
	if werr := call(t, m, peer, protocol.TypeTerminalOpen, openReq(2, "plain"), nil); werr != nil {
		t.Fatalf("open: %+v", werr)
	}
	if challenger != nil || len(v.attempts) != 1 {
		t.Fatal("a page that answers no prompts got a challenger")
	}

	v.refuse = fault.New(fault.Busy, "Connection request already in progress")
	req = openReq(3, "ki2")
	req.Target.Interactive = true
	if werr := call(t, m, peer, protocol.TypeTerminalOpen, req, nil); werr == nil || werr.Code != fault.Busy {
		t.Fatalf("provider refusal: %+v", werr)
	}
}
