package principal_test

import (
	"context"
	"regexp"
	"testing"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/principal/principaltest"
)

func TestRequire(t *testing.T) {
	t.Parallel()
	user := principaltest.User(7)
	admin := principaltest.Admin(1)
	recovery := principaltest.Admin(2)
	recovery.Recovery = true
	tests := []struct {
		name      string
		ctx       context.Context
		require   func(context.Context) (principal.Principal, error)
		wantCode  fault.Code
		wantOwner int64
	}{
		{name: "no principal", ctx: t.Context(), require: principal.Require, wantCode: fault.AuthenticationNeeded},
		{name: "invalid principal", ctx: principal.With(t.Context(), principal.Principal{UserID: 1}), require: principal.Require, wantCode: fault.AuthenticationNeeded},
		{name: "user", ctx: principal.With(t.Context(), user), require: principal.Require, wantOwner: 7},
		{name: "recovery refused", ctx: principal.With(t.Context(), recovery), require: principal.Require, wantCode: fault.Forbidden},
		{name: "recovery for repair", ctx: principal.With(t.Context(), recovery), require: principal.RequireAllowingRecovery, wantOwner: 2},
		{name: "admin", ctx: principal.With(t.Context(), admin), require: principal.RequireAdmin, wantOwner: 1},
		{name: "user is not admin", ctx: principal.With(t.Context(), user), require: principal.RequireAdmin, wantCode: fault.Forbidden},
		{name: "recovery admin is not admin", ctx: principal.With(t.Context(), recovery), require: principal.RequireAdmin, wantCode: fault.Forbidden},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			p, err := tt.require(tt.ctx)
			if code := fault.CodeOf(err); code != tt.wantCode {
				t.Fatalf("code = %q, want %q (err %v)", code, tt.wantCode, err)
			}
			if p.UserID != tt.wantOwner {
				t.Fatalf("UserID = %d, want %d", p.UserID, tt.wantOwner)
			}
		})
	}
}

var actionForm = regexp.MustCompile(`^[a-z0-9][a-z0-9_.:-]{0,95}$`)

func TestActions(t *testing.T) {
	t.Parallel()
	seen := map[principal.Action]bool{}
	for _, a := range principal.Actions() {
		if seen[a] || !a.Known() {
			t.Errorf("action %q duplicate or unknown", a)
		}
		// The Python release accepts only this form (step_up.normalize_action).
		if !actionForm.MatchString(string(a)) {
			t.Errorf("action %q does not have the form of a step-up action", a)
		}
		seen[a] = true
	}
	if len(seen) == 0 || principal.Action("key.upload ").Known() {
		t.Errorf("catalog has %d actions or accepts a near miss", len(seen))
	}
	principal.Actions()[0] = "mutated"
	if !principal.ActionKeyUpload.Known() {
		t.Error("Actions exposes the catalog for mutation")
	}
}

func TestStepUpDouble(t *testing.T) {
	t.Parallel()
	var s principaltest.StepUp
	p := principaltest.User(3)
	s.Issue(p, principal.ActionKeyDelete, "key-1", "g1")
	other := p
	other.SessionID = "other"
	cases := []struct {
		name string
		p    principal.Principal
		a    principal.Action
		tgt  string
		want fault.Code
	}{
		{name: "other session", p: other, a: principal.ActionKeyDelete, tgt: "key-1", want: fault.StepUpRequired},
		{name: "other action", p: p, a: principal.ActionKeyUpload, tgt: "key-1", want: fault.StepUpRequired},
		{name: "other target", p: p, a: principal.ActionKeyDelete, tgt: "key-2", want: fault.StepUpRequired},
		{name: "match", p: p, a: principal.ActionKeyDelete, tgt: "key-1"},
		{name: "replay", p: p, a: principal.ActionKeyDelete, tgt: "key-1", want: fault.StepUpRequired},
	}
	for _, c := range cases {
		if got := fault.CodeOf(s.Consume(t.Context(), c.p, c.a, c.tgt, "g1")); got != c.want {
			t.Errorf("%s: code %q, want %q", c.name, got, c.want)
		}
	}
	if len(s.Calls()) != len(cases) {
		t.Errorf("recorded %d calls", len(s.Calls()))
	}
}

func TestRevocationsDouble(t *testing.T) {
	t.Parallel()
	var r principaltest.Revocations
	var got []principal.Revocation
	cancel := r.Subscribe(func(rev principal.Revocation) { got = append(got, rev) })
	r.Revoke(principal.Revocation{SessionID: "s1", UserID: 1, Reason: principal.ReasonLogout})
	cancel()
	r.Revoke(principal.Revocation{SessionID: "s2", UserID: 1, Reason: principal.ReasonLogout})
	if len(got) != 1 || got[0].SessionID != "s1" {
		t.Fatalf("delivered %+v", got)
	}
}
