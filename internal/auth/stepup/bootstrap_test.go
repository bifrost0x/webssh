package stepup

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bifrost0x/webssh/internal/auth"
	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
)

type fakeBootstrap struct {
	live  map[principal.Action]bool
	code  string
	spent int
}

func (f *fakeBootstrap) Live(_ context.Context, _ int64, a principal.Action) (bool, error) {
	return f.live[a], nil
}

func (f *fakeBootstrap) Redeem(_ context.Context, _ int64, a principal.Action, code string) (bool, error) {
	if !f.live[a] || code != f.code {
		return false, nil
	}
	f.spent++
	f.live[a] = false
	return true, nil
}

// A GitHub-only account without factors confirms its first factor with
// an operator's code; nothing else gets the method.
func TestBootstrapMethod(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.svc.Passwords = fakePasswords{}
	boot := &fakeBootstrap{live: map[principal.Action]bool{principal.ActionPasskeyEnroll: true}, code: "the-code"}
	e.svc.Bootstrap = boot
	p := principal.Principal{UserID: 5, SessionID: "s1", Username: "octo"}
	ctx := t.Context()

	// Without a GitHub sign-in in this session: no method at all.
	if _, err := e.svc.Begin(ctx, p, principal.ActionPasskeyEnroll, "", ChannelAccount); !fault.Is(err, fault.StepUpFailed) {
		t.Fatalf("password session: %v", err)
	}
	e.sessions.byID["s1"] = SessionAssurance{Level: auth.AssuranceBasic, Methods: []string{"github"}}
	// Another action has no live code.
	if _, err := e.svc.Begin(ctx, p, principal.ActionTOTPEnroll, "", ChannelAccount); !fault.Is(err, fault.StepUpFailed) {
		t.Fatalf("other action: %v", err)
	}
	c, err := e.svc.Begin(ctx, p, principal.ActionPasskeyEnroll, "", ChannelAccount)
	if err != nil || len(c.Methods) != 1 || c.Methods[0] != MethodBootstrap {
		t.Fatalf("plan %+v %v", c, err)
	}
	if _, err := e.svc.Prove(ctx, p, c.Intent, Proof{Method: MethodBootstrap, Secret: "wrong"}); !fault.Is(err, fault.StepUpFailed) {
		t.Fatalf("wrong code: %v", err)
	}
	if _, err := e.svc.Prove(ctx, p, c.Intent, Proof{Method: MethodPassword, Secret: "x"}); err == nil {
		t.Fatal("password accepted for a bootstrap intent")
	}
	g, err := e.svc.Prove(ctx, p, c.Intent, Proof{Method: MethodBootstrap, Secret: "the-code"})
	if err != nil || boot.spent != 1 {
		t.Fatalf("prove: %v", err)
	}
	if err := e.svc.Consume(ctx, p, principal.ActionPasskeyEnroll, "5", g); err != nil {
		t.Fatalf("consume: %v", err)
	}

	// An account with a factor gets its factor, not the code.
	boot.live[principal.ActionPasskeyEnroll] = true
	e.passkeys.enrolled[5] = true
	c, err = e.svc.Begin(ctx, p, principal.ActionPasskeyEnroll, "", ChannelAccount)
	if err != nil || c.Methods[0] != MethodPasskey || len(c.Methods) != 1 {
		t.Fatalf("with passkey: %+v %v", c, err)
	}
	// A recovery session never gets it.
	e.passkeys.enrolled[5] = false
	pr := p
	pr.Recovery = true
	if _, err := e.svc.Begin(ctx, pr, principal.ActionPasskeyEnroll, "", ChannelAccount); err == nil {
		t.Fatal("recovery session offered the code")
	}
}

func TestBootstrapRoute(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.svc.Passwords = fakePasswords{}
	e.svc.Bootstrap = &fakeBootstrap{live: map[principal.Action]bool{principal.ActionTOTPEnroll: true}, code: "the-code"}
	e.sessions.byID["s1"] = SessionAssurance{Level: auth.AssuranceBasic, Methods: []string{"github"}}
	p := principal.Principal{UserID: 5, SessionID: "s1"}
	c, err := e.svc.Begin(t.Context(), p, principal.ActionTOTPEnroll, "", ChannelAccount)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	(&HTTP{Service: e.svc}).RegisterBootstrap(mux)
	post := func(body string) *httptest.ResponseRecorder {
		r := httptest.NewRequestWithContext(principal.With(t.Context(), p), "POST", "/api/account/step-up/bootstrap", strings.NewReader(body))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, r)
		return rec
	}
	if rec := post(`{"intent":"` + c.Intent + `","code":"nope"}`); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "step_up_failed") {
		t.Fatalf("wrong code: %d %s", rec.Code, rec.Body)
	}
	rec := post(`{"intent":"` + c.Intent + `","code":"the-code"}`)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"method":"bootstrap"`) {
		t.Fatalf("code: %d %s", rec.Code, rec.Body)
	}
}
