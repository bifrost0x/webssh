package stepup

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/bifrost0x/webssh/internal/auth"
	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/principal/principaltest"
)

// fakeProvider is the OIDC method: offered to sessions that signed in
// with it while linked is set.
type fakeProvider struct{ linked bool }

func (fakeProvider) Method() string   { return "oidc" }
func (fakeProvider) ReachesMFA() bool { return true }
func (f fakeProvider) Offered(_ context.Context, _ principal.Principal, sa SessionAssurance) (bool, error) {
	return f.linked && slices.Contains(sa.Methods, "oidc"), nil
}

func oidcEnv(t *testing.T) (*env, principal.Principal) {
	t.Helper()
	e := newEnv(t)
	e.svc.External = []ExternalMethod{fakeProvider{linked: true}}
	p := principaltest.User(5)
	e.sessions.byID[p.SessionID] = SessionAssurance{Level: auth.AssuranceBasic, Methods: []string{"oidc"}}
	return e, p
}

func TestExternalMethodOrder(t *testing.T) {
	t.Parallel()
	e, p := oidcEnv(t)
	ctx := t.Context()
	plan, _, err := e.svc.Plan(ctx, p, principal.ActionKeyReplace, "k", ChannelAccount)
	if err != nil || !slices.Equal(plan.Methods, []string{"oidc"}) {
		t.Fatalf("provider session: %+v %v", plan, err)
	}
	e.accounts.mfa[5], e.totp.enrolled[5] = true, true
	plan, _, err = e.svc.Plan(ctx, p, principal.ActionKeyReplace, "k", ChannelAccount)
	if err != nil || !slices.Equal(plan.Methods, []string{"oidc", MethodTOTP}) {
		t.Fatalf("with MFA: %+v %v", plan, err)
	}
	// A password session is not offered the provider.
	pw := principaltest.User(6)
	if plan, _, _ := e.svc.Plan(ctx, pw, principal.ActionKeyReplace, "k", ChannelAccount); slices.Contains(plan.Methods, "oidc") {
		t.Fatalf("password session: %+v", plan)
	}
	e.svc.External = []ExternalMethod{fakeProvider{linked: false}}
	e.accounts.mfa[5] = false
	if _, _, err := e.svc.Plan(ctx, p, principal.ActionKeyReplace, "k", ChannelAccount); !fault.Is(err, fault.StepUpFailed) {
		t.Fatalf("unlinked provider session without password: %v", err)
	}
}

func TestProveExternal(t *testing.T) {
	t.Parallel()
	e, p := oidcEnv(t)
	ctx := t.Context()
	c, err := e.svc.Begin(ctx, p, principal.ActionKeyReplace, "k", ChannelAccount)
	if err != nil {
		t.Fatal(err)
	}
	if req, err := e.svc.ExternalIntent(ctx, p, c.Intent, "oidc"); err != nil || req != auth.AssuranceBasic {
		t.Fatalf("intent: %s %v", req, err)
	}
	if _, err := e.svc.ExternalIntent(ctx, p, c.Intent, MethodPassword); err == nil {
		t.Fatal("password accepted as external method")
	}
	// Another session cannot complete the intent.
	other := principaltest.User(5)
	other.SessionID = "other-session"
	if _, err := e.svc.ProveExternal(ctx, other, c.Intent, "oidc", auth.AssuranceMFA); !fault.Is(err, fault.StepUpFailed) {
		t.Fatalf("foreign session: %v", err)
	}
	if _, pending, err := e.svc.ExternalStatus(ctx, p, c.Intent); err != nil || !pending {
		t.Fatalf("status before proof: %v %v", pending, err)
	}
	grant, err := e.svc.ProveExternal(ctx, p, c.Intent, "oidc", auth.AssuranceBasic)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.ProveExternal(ctx, p, c.Intent, "oidc", auth.AssuranceBasic); !fault.Is(err, fault.StepUpFailed) {
		t.Fatalf("second proof: %v", err)
	}
	// The page claims the grant once, from the same session only.
	if _, _, err := e.svc.ExternalStatus(ctx, other, c.Intent); !fault.Is(err, fault.StepUpFailed) {
		t.Fatalf("foreign status: %v", err)
	}
	got, pending, err := e.svc.ExternalStatus(ctx, p, c.Intent)
	if err != nil || pending || got != grant {
		t.Fatalf("status: %q %v %v", got, pending, err)
	}
	if _, _, err := e.svc.ExternalStatus(ctx, p, c.Intent); !fault.Is(err, fault.StepUpFailed) {
		t.Fatalf("claimed twice: %v", err)
	}
	if err := e.svc.Consume(ctx, p, principal.ActionKeyReplace, "k", grant); err != nil {
		t.Fatal(err)
	}
}

func TestProveExternalNeedsTheRequiredAssurance(t *testing.T) {
	t.Parallel()
	e, p := oidcEnv(t)
	e.accounts.mfa[5] = true
	ctx := t.Context()
	c, err := e.svc.Begin(ctx, p, principal.ActionKeyReplace, "k", ChannelAccount)
	if err != nil {
		t.Fatal(err)
	}
	if req, err := e.svc.ExternalIntent(ctx, p, c.Intent, "oidc"); err != nil || req != auth.AssuranceMFA {
		t.Fatalf("intent: %s %v", req, err)
	}
	if _, err := e.svc.ProveExternal(ctx, p, c.Intent, "oidc", auth.AssuranceBasic); !fault.Is(err, fault.StepUpFailed) {
		t.Fatalf("BASIC answer for an MFA intent: %v", err)
	}
	if _, err := e.svc.ProveExternal(ctx, p, c.Intent, "oidc", auth.AssurancePhishingResistant); err != nil {
		t.Fatal(err)
	}
}

func TestBeginExternalAdmin(t *testing.T) {
	t.Parallel()
	e, _ := oidcEnv(t)
	ctx := t.Context()
	admin := principaltest.Admin(7)
	e.sessions.byID[admin.SessionID] = SessionAssurance{Level: auth.AssuranceBasic, Methods: []string{"oidc"}}
	token, err := e.svc.BeginExternal(ctx, admin, principal.ActionUserManage, "3:lock", "oidc")
	if err != nil {
		t.Fatal(err)
	}
	grant, err := e.svc.ProveExternal(ctx, admin, token, "oidc", auth.AssuranceMFA)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Consume(ctx, admin, principal.ActionUserManage, "3:lock", grant); err != nil {
		t.Fatal(err)
	}
	// An admin grant is not left for the account status poll.
	if _, _, err := e.svc.ExternalStatus(ctx, admin, token); !fault.Is(err, fault.StepUpFailed) {
		t.Fatalf("admin status: %v", err)
	}
	pw := principaltest.Admin(8)
	if _, err := e.svc.BeginExternal(ctx, pw, principal.ActionUserManage, "3:lock", "oidc"); !fault.Is(err, fault.StepUpFailed) {
		t.Fatalf("password session began a provider step-up: %v", err)
	}
}

func TestStatusRoute(t *testing.T) {
	t.Parallel()
	e, p := oidcEnv(t)
	mux := http.NewServeMux()
	(&HTTP{Service: e.svc}).Register(mux)
	c, err := e.svc.Begin(t.Context(), p, principal.ActionKeyReplace, "k", ChannelAccount)
	if err != nil {
		t.Fatal(err)
	}
	post := func(body string) *httptest.ResponseRecorder {
		r := httptest.NewRequestWithContext(principal.With(t.Context(), p), "POST", "/api/account/step-up/status", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}
	if w := post(`{"intent":"` + c.Intent + `"}`); w.Code != 200 || !strings.Contains(w.Body.String(), `"pending"`) {
		t.Fatalf("pending: %d %s", w.Code, w.Body)
	}
	grant, err := e.svc.ProveExternal(t.Context(), p, c.Intent, "oidc", auth.AssuranceBasic)
	if err != nil {
		t.Fatal(err)
	}
	if w := post(`{"intent":"` + c.Intent + `"}`); w.Code != 200 || !strings.Contains(w.Body.String(), grant) || !strings.Contains(w.Body.String(), `"completed"`) {
		t.Fatalf("completed: %d %s", w.Code, w.Body)
	}
	if w := post(`{"intent":"` + c.Intent + `"}`); w.Code != http.StatusGone || !strings.Contains(w.Body.String(), "step_up_expired") {
		t.Fatalf("claimed: %d %s", w.Code, w.Body)
	}
}
