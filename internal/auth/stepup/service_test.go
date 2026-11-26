package stepup

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/auth"
	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/principal/principaltest"
	"github.com/bifrost0x/webssh/internal/store"
)

// grantFor runs the password step-up for action and target.
func (e *env) grantFor(t *testing.T, p principal.Principal, action principal.Action, target string) string {
	t.Helper()
	c, err := e.svc.Begin(t.Context(), p, action, target, ChannelAccount)
	if err != nil {
		t.Fatalf("Begin(%s, %q): %v", action, target, err)
	}
	grant, err := e.svc.Prove(t.Context(), p, c.Intent, Proof{Method: MethodPassword, Secret: "secret"})
	if err != nil {
		t.Fatalf("Prove: %v", err)
	}
	return grant
}

func TestConsumeChecksEveryBinding(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ctx := t.Context()
	p := principaltest.User(1)
	otherSession := p
	otherSession.SessionID = "session-x"
	tests := []struct {
		name   string
		p      principal.Principal
		action principal.Action
		target string
		mutate func()
	}{
		{"other session", otherSession, principal.ActionKeyDelete, "k1", nil},
		{"other user", principaltest.User(2), principal.ActionKeyDelete, "k1", nil},
		{"other action", p, principal.ActionKeyReplace, "k1", nil},
		{"other target", p, principal.ActionKeyDelete, "k2", nil},
		{"empty target", p, principal.ActionKeyDelete, "", nil},
		{"unknown action", p, principal.Action("key.export"), "k1", nil},
		{"expired", p, principal.ActionKeyDelete, "k1", func() { e.clock.Advance(GrantTTL) }},
		{"MFA turned on since", p, principal.ActionKeyDelete, "k1", func() { e.accounts.mfa[1] = true }},
	}
	for _, tt := range tests {
		e.accounts.mfa[1] = false
		grant := e.grantFor(t, p, principal.ActionKeyDelete, "k1")
		if tt.mutate != nil {
			tt.mutate()
		}
		err := e.svc.Consume(ctx, tt.p, tt.action, tt.target, grant)
		if !fault.Is(err, fault.StepUpRequired) {
			t.Errorf("%s: %v, want step_up_required", tt.name, err)
		}
		// The grant is spent even by a refused attempt.
		e.accounts.mfa[1] = false
		if err := e.svc.Consume(ctx, p, principal.ActionKeyDelete, "k1", grant); err == nil {
			t.Errorf("%s: the grant survived a refused attempt", tt.name)
		}
	}
	grant := e.grantFor(t, p, principal.ActionKeyDelete, "k1")
	if err := e.svc.Consume(ctx, p, principal.ActionKeyDelete, "k1", grant); err != nil {
		t.Fatalf("valid grant: %v", err)
	}
	if err := e.svc.Consume(ctx, p, principal.ActionKeyDelete, "k1", grant); !fault.Is(err, fault.StepUpRequired) {
		t.Fatalf("grant used twice: %v", err)
	}
	for _, g := range []string{"", "x", string(make([]byte, 300))} {
		if err := e.svc.Consume(ctx, p, principal.ActionKeyDelete, "k1", g); !fault.Is(err, fault.StepUpRequired) {
			t.Errorf("grant %q: %v", g, err)
		}
	}
}

// Every action of the catalog can be granted and consumed by the service,
// so no consumer is left without a way to get a grant.
func TestCatalogIsServed(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	p := principaltest.Admin(1)
	e.passkeys.enrolled[1] = true
	e.svc.Targets = map[principal.Action]TargetCheck{}
	for _, action := range principal.Actions() {
		target := "t-1"
		switch {
		case slices.Contains(selfActions, action):
			target = ""
		}
		e.accounts.mfa[1] = action == principal.ActionMFADisable
		if action == principal.ActionMFADisable {
			e.totp.enrolled[1] = true
		}
		c, err := e.svc.Begin(t.Context(), p, action, target, ChannelAccount)
		if err != nil {
			t.Errorf("%s: Begin: %v", action, err)
			continue
		}
		method := c.Methods[0]
		proof := Proof{Method: method, Secret: "secret"}
		if method == MethodPasskey {
			if _, err := e.svc.PasskeyOptions(t.Context(), p, c.Intent); err != nil {
				t.Fatal(err)
			}
			proof.Credential = []byte(`{"id":"good"}`)
		}
		grant, err := e.svc.Prove(t.Context(), p, c.Intent, proof)
		if err != nil {
			t.Errorf("%s: Prove(%s): %v", action, method, err)
			continue
		}
		if target == "" {
			target = "1"
		}
		if err := e.svc.Consume(t.Context(), p, action, target, grant); err != nil {
			t.Errorf("%s: Consume: %v", action, err)
		}
	}
}

func TestPlanMethods(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ctx := t.Context()
	p := principaltest.User(3)
	plan, _, err := e.svc.Plan(ctx, p, principal.ActionKeyReplace, "k", ChannelAccount)
	if err != nil || !slices.Equal(plan.Methods, []string{MethodPassword}) || plan.Required != auth.AssuranceBasic {
		t.Fatalf("without MFA: %+v %v", plan, err)
	}
	e.accounts.mfa[3], e.totp.enrolled[3], e.passkeys.enrolled[3] = true, true, true
	plan, _, err = e.svc.Plan(ctx, p, principal.ActionKeyReplace, "k", ChannelAccount)
	if err != nil || !slices.Equal(plan.Methods, []string{MethodPasskey, MethodTOTP}) || plan.Required != auth.AssuranceMFA {
		t.Fatalf("with MFA: %+v %v", plan, err)
	}
	e.svc.Gates = fakeGates{auth.FeatureTOTP: true}
	if plan, _, _ = e.svc.Plan(ctx, p, principal.ActionKeyReplace, "k", ChannelAccount); !slices.Equal(plan.Methods, []string{MethodTOTP}) {
		t.Fatalf("passkeys off: %+v", plan)
	}
	e.totp.enrolled[3] = false
	if _, _, err := e.svc.Plan(ctx, p, principal.ActionKeyReplace, "k", ChannelAccount); !fault.Is(err, fault.StepUpFailed) {
		t.Fatalf("MFA without a usable factor: %v", err)
	}
	// A recovery session gets no grant.
	rp := principaltest.User(4)
	rp.Recovery = true
	if _, _, err := e.svc.Plan(ctx, rp, principal.ActionKeyReplace, "k", ChannelAccount); !fault.Is(err, fault.StepUpFailed) {
		t.Fatalf("recovery session: %v", err)
	}
	e.sessions.revoked[p.SessionID] = true
	if _, _, err := e.svc.Plan(ctx, p, principal.ActionKeyReplace, "k", ChannelAccount); !fault.Is(err, fault.StepUpFailed) {
		t.Fatalf("revoked session: %v", err)
	}
}

func TestTargetRules(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ctx := t.Context()
	p := principaltest.User(5)
	refused := func(name string, action principal.Action, target string) {
		t.Helper()
		if _, _, err := e.svc.Plan(ctx, p, action, target, ChannelAccount); !fault.Is(err, fault.InvalidRequest) {
			t.Errorf("%s: %v, want invalid_request", name, err)
		}
	}
	refused("unknown action", "server.operation", "x")
	refused("admin action", principal.ActionUserCreate, "bob")
	refused("other account", principal.ActionTOTPEnroll, "6")
	refused("empty target", principal.ActionKeyDelete, "")
	refused("long target", principal.ActionKeyDelete, string(make([]byte, MaxTargetBytes+1)))
	refused("MFA already off", principal.ActionMFADisable, "")
	refused("no passkey to enable MFA with", principal.ActionMFAEnable, "")
	e.svc.Targets = map[principal.Action]TargetCheck{principal.ActionTOTPDelete: func(context.Context, principal.Principal, string) error {
		return errors.New("not yours")
	}}
	refused("target check", principal.ActionTOTPDelete, "9")
	e.svc.Gates = fakeGates{}
	refused("feature off", principal.ActionTOTPEnroll, "")
	if _, target, err := e.svc.Plan(ctx, p, principal.ActionRecoveryRotate, "", ChannelAccount); err == nil || target != "" {
		t.Errorf("recovery.rotate with recovery off: %q %v", target, err)
	}
	e.svc.Gates = fakeGates{auth.FeatureTOTP: true}
	if _, target, err := e.svc.Plan(ctx, p, principal.ActionTOTPEnroll, "", ChannelAccount); err != nil || target != "5" {
		t.Errorf("self target default: %q %v", target, err)
	}
	if _, _, err := e.svc.Plan(ctx, principaltest.Admin(7), principal.ActionUserCreate, "bob", ChannelAdmin); err != nil {
		t.Errorf("admin action by an admin: %v", err)
	}
}

func TestRecentStrongSignIn(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ctx := t.Context()
	p := principaltest.User(8)
	e.accounts.mfa[8], e.totp.enrolled[8] = true, true
	e.sessions.byID[p.SessionID] = SessionAssurance{Level: auth.AssuranceMFA, StrongAt: e.clock.Now(), Methods: []string{"password", "totp"}}
	c, err := e.svc.Begin(ctx, p, principal.ActionKeyReplace, "k", ChannelAccount)
	if err != nil || c.Grant == "" || c.Intent != "" {
		t.Fatalf("recent: %+v %v", c, err)
	}
	if err := e.svc.Consume(ctx, p, principal.ActionKeyReplace, "k", c.Grant); err != nil {
		t.Fatal(err)
	}
	if c, err = e.svc.BeginCeremony(ctx, p, principal.ActionKeyReplace, "k", ChannelAdmin); err != nil || c.Grant != "" {
		t.Fatalf("ceremony: %+v %v", c, err)
	}
	e.clock.Advance(301 * time.Second)
	if c, err = e.svc.Begin(ctx, p, principal.ActionKeyReplace, "k", ChannelAccount); err != nil || c.Grant != "" {
		t.Fatalf("after the window: %+v %v", c, err)
	}
	// BASIC sign-ins never count as recent.
	q := principaltest.User(9)
	e.sessions.byID[q.SessionID] = SessionAssurance{Level: auth.AssuranceBasic, StrongAt: e.clock.Now(), Methods: []string{"password"}}
	if c, _ = e.svc.Begin(ctx, q, principal.ActionKeyReplace, "k", ChannelAccount); c.Grant != "" {
		t.Fatal("a BASIC session got a grant without proof")
	}
}

func TestProveRules(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ctx := t.Context()
	p := principaltest.User(10)
	c, err := e.svc.Begin(ctx, p, principal.ActionKeyReplace, "k", ChannelAccount)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Prove(ctx, p, c.Intent, Proof{Method: MethodPassword, Secret: "wrong"}); !Rejected(err) {
		t.Fatalf("wrong password: %v", err)
	}
	if _, err := e.svc.Prove(ctx, p, c.Intent, Proof{Method: MethodTOTP, Secret: "123456"}); !fault.Is(err, fault.StepUpFailed) || Rejected(err) {
		t.Fatalf("method not offered: %v", err)
	}
	other := p
	other.SessionID = "elsewhere"
	if _, err := e.svc.Prove(ctx, other, c.Intent, Proof{Method: MethodPassword, Secret: "secret"}); !fault.Is(err, fault.StepUpFailed) {
		t.Fatalf("intent from another session: %v", err)
	}
	grant, err := e.svc.Prove(ctx, p, c.Intent, Proof{Method: MethodPassword, Secret: "secret"})
	if err != nil {
		t.Fatalf("retry after a wrong password: %v", err)
	}
	if _, err := e.svc.Prove(ctx, p, c.Intent, Proof{Method: MethodPassword, Secret: "secret"}); err == nil {
		t.Fatal("an intent issued two grants")
	}
	if err := e.svc.Consume(ctx, p, principal.ActionKeyReplace, "k", grant); err != nil {
		t.Fatal(err)
	}
	// MFA switched on after the intent: start again.
	c, _ = e.svc.Begin(ctx, p, principal.ActionKeyReplace, "k", ChannelAccount)
	e.accounts.mfa[10] = true
	if _, err := e.svc.Prove(ctx, p, c.Intent, Proof{Method: MethodPassword, Secret: "secret"}); err == nil {
		t.Fatal("a BASIC intent completed after MFA was turned on")
	}
	// Expired intent.
	e.accounts.mfa[10] = false
	c, _ = e.svc.Begin(ctx, p, principal.ActionKeyReplace, "k", ChannelAccount)
	e.clock.Advance(IntentTTL)
	if _, err := e.svc.Prove(ctx, p, c.Intent, Proof{Method: MethodPassword, Secret: "secret"}); err == nil {
		t.Fatal("expired intent completed")
	}
}

func TestTOTPProofAndThrottle(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ctx := t.Context()
	p := principaltest.User(11)
	e.accounts.mfa[11], e.totp.enrolled[11] = true, true
	c, err := e.svc.Begin(ctx, p, principal.ActionKeyDelete, "k", ChannelAccount)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Prove(ctx, p, c.Intent, Proof{Method: MethodPassword, Secret: "secret"}); err == nil {
		t.Fatal("password accepted where MFA is required")
	}
	for range 3 {
		if _, err := e.svc.Prove(ctx, p, c.Intent, Proof{Method: MethodTOTP, Secret: "000000"}); !Rejected(err) {
			t.Fatalf("wrong code: %v", err)
		}
	}
	if _, err := e.svc.Prove(ctx, p, c.Intent, Proof{Method: MethodTOTP, Secret: "123456"}); !fault.Is(err, fault.RateLimited) {
		t.Fatalf("throttled: %v", err)
	}
	e.totp.failures = 0
	grant, err := e.svc.Prove(ctx, p, c.Intent, Proof{Method: MethodTOTP, Secret: "123456"})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Consume(ctx, p, principal.ActionKeyDelete, "k", grant); err != nil {
		t.Fatalf("MFA grant: %v", err)
	}
}

func TestLimits(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ctx := t.Context()
	p := principaltest.User(12)
	for i := range MaxIntentsPerSess {
		if _, err := e.svc.Begin(ctx, p, principal.ActionKeyDelete, "k", ChannelAccount); err != nil {
			t.Fatalf("intent %d: %v", i, err)
		}
	}
	if _, err := e.svc.Begin(ctx, p, principal.ActionKeyDelete, "k", ChannelAccount); !fault.Is(err, fault.InvalidRequest) {
		t.Fatalf("ninth intent: %v", err)
	}
	// Admin intents replace each other.
	a := principaltest.Admin(13)
	for range 20 {
		if _, err := e.svc.BeginCeremony(ctx, a, principal.ActionUserCreate, "bob", ChannelAdmin); err != nil {
			t.Fatal(err)
		}
	}
	e.clock.Advance(IntentTTL)
	var grants []string
	for range MaxGrantsPerSess + 2 {
		grants = append(grants, e.grantFor(t, p, principal.ActionKeyDelete, "k"))
	}
	var n int
	_ = e.svc.DB.Read(ctx, func(tx *store.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT count(*) FROM stepup_grants WHERE session_id = ?`, p.SessionID).Scan(&n)
	})
	if n != MaxGrantsPerSess {
		t.Fatalf("%d live grants, want %d", n, MaxGrantsPerSess)
	}
	if err := e.svc.Consume(ctx, p, principal.ActionKeyDelete, "k", grants[0]); err == nil {
		t.Fatal("the oldest grant survived the limit")
	}
	if err := e.svc.Consume(ctx, p, principal.ActionKeyDelete, "k", grants[len(grants)-1]); err != nil {
		t.Fatal(err)
	}
}

func TestStoredFormsAreNotTheTokens(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ctx := t.Context()
	p := principaltest.User(14)
	grant := e.grantFor(t, p, principal.ActionKeyDelete, "k")
	var stored []byte
	_ = e.svc.DB.Read(ctx, func(tx *store.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT token_mac FROM stepup_grants`).Scan(&stored)
	})
	if string(stored) == grant || len(stored) != 32 {
		t.Fatal("the grant is stored in clear")
	}
}
