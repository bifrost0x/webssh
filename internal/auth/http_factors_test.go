package auth

import (
	json "encoding/json/v2"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/principal/principaltest"
)

type factorEnv struct {
	h        *FactorHTTP
	mux      *http.ServeMux
	accounts *fakeAccounts
	totp     *fakeTOTP
	pending  *fakePending
	stepUp   *grantStepUp
	limiter  *countingLimiter
	audit    *recordingAudit
}

func newFactorEnv(t *testing.T) *factorEnv {
	t.Helper()
	m, accounts, totp, _ := newMFA(t)
	e := &factorEnv{accounts: accounts, totp: totp, pending: &fakePending{}, stepUp: &grantStepUp{}, limiter: &countingLimiter{limit: 100}, audit: &recordingAudit{}}
	e.h = &FactorHTTP{
		MFA: m, Recovery: &Recovery{DB: m.DB, iterations: 1}, Throttle: &Throttle{DB: m.DB},
		StepUp: e.stepUp, Pending: e.pending, Root: "/ssh", Audit: e.audit,
		Limits: FactorLimits{Limiter: e.limiter, Enabled: true, Login: Rule{5, time.Minute}, Reauth: Rule{10, time.Minute}, ClientAddr: func(*http.Request) string { return "192.0.2.1" }},
	}
	e.mux = http.NewServeMux()
	e.h.Register(e.mux)
	return e
}

func (e *factorEnv) do(t *testing.T, p *principal.Principal, method, path, body, grant string) (int, map[string]any) {
	t.Helper()
	r := httptest.NewRequestWithContext(t.Context(), method, path, strings.NewReader(body))
	if p != nil {
		r = r.WithContext(principal.With(r.Context(), *p))
	}
	if grant != "" {
		r.Header.Set(StepUpHeader, grant)
	}
	w := httptest.NewRecorder()
	e.mux.ServeHTTP(w, r)
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("%s %s: body %q: %v", method, path, w.Body.String(), err)
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("%s %s: response may be cached", method, path)
	}
	return w.Code, out
}

func TestDisableMFARoute(t *testing.T) {
	t.Parallel()
	e := newFactorEnv(t)
	p := principaltest.User(2)
	e.accounts.mfa[2], e.totp.count[2] = true, 1
	if code, out := e.do(t, &p, "POST", "/api/account/mfa/disable", `{}`, "ok"); code != 400 || out["code"] != "invalid_request" {
		t.Fatalf("unconfirmed: %d %v", code, out)
	}
	e.stepUp.action, e.stepUp.target = principal.ActionMFADisable, "2"
	if code, out := e.do(t, &p, "POST", "/api/account/mfa/disable", `{"confirm_disable_mfa": true}`, ""); code != 403 || out["code"] != "step_up_required" {
		t.Fatalf("without grant: %d %v", code, out)
	}
	if !e.accounts.mfa[2] {
		t.Fatal("MFA turned off without a grant")
	}
	if code, out := e.do(t, &p, "POST", "/api/account/mfa/disable", `{"confirm_disable_mfa": true}`, "ok"); code != 200 || out["ok"] != true {
		t.Fatalf("with grant: %d %v", code, out)
	}
	if e.accounts.mfa[2] || e.totp.count[2] != 0 {
		t.Fatal("MFA still on")
	}
	if code, out := e.do(t, &p, "POST", "/api/account/mfa/disable", `{"confirm_disable_mfa": true}`, "ok"); code != 409 {
		t.Fatalf("second disable: %d %v", code, out)
	}
	if code, _ := e.do(t, nil, "POST", "/api/account/mfa/disable", `{"confirm_disable_mfa": true}`, "ok"); code != 401 {
		t.Fatalf("anonymous: %d", code)
	}
	rp := principaltest.User(2)
	rp.Recovery = true
	if code, _ := e.do(t, &rp, "POST", "/api/account/mfa/disable", `{"confirm_disable_mfa": true}`, "ok"); code != 403 {
		t.Fatalf("recovery session on the account route: %d", code)
	}
}

func TestDisableMFAAfterRecoveryRoute(t *testing.T) {
	t.Parallel()
	e := newFactorEnv(t)
	p := principaltest.User(3)
	e.accounts.mfa[3] = true
	if code, _ := e.do(t, &p, "POST", "/api/auth/mfa/disable", `{"confirm_username": "user3"}`, ""); code != 403 {
		t.Fatalf("ordinary session: %d", code)
	}
	p.Recovery = true
	if code, _ := e.do(t, &p, "POST", "/api/auth/mfa/disable", `{"confirm_username": "user4"}`, ""); code != 400 {
		t.Fatalf("wrong name: %d", code)
	}
	if code, out := e.do(t, &p, "POST", "/api/auth/mfa/disable", `{"confirm_username": "user3"}`, ""); code != 200 || out["ok"] != true {
		t.Fatalf("recovery disable: %d %v", code, out)
	}
	if e.accounts.mfa[3] {
		t.Fatal("MFA still on")
	}
}

func TestRecoveryCodeRoutes(t *testing.T) {
	t.Parallel()
	e := newFactorEnv(t)
	p := principaltest.User(4)
	e.stepUp.action, e.stepUp.target = principal.ActionRecoveryRotate, "4"
	if code, _ := e.do(t, &p, "POST", "/api/recovery-codes", ``, "bad"); code != 403 {
		t.Fatalf("rotate without grant: %d", code)
	}
	code, out := e.do(t, &p, "POST", "/api/recovery-codes", ``, "ok")
	codes, _ := out["codes"].([]any)
	if code != 200 || len(codes) != 10 {
		t.Fatalf("rotate: %d %v", code, out)
	}

	// Recovery sign-in.
	e.pending.login = PendingLogin{UserID: 4, PrimaryMethod: "password"}
	if code, out := e.do(t, nil, "POST", "/api/auth/recovery", `{"code": "`+codes[0].(string)+`"}`, ""); code != 401 || out["error"] != "Recovery authentication failed" {
		t.Fatalf("recovery without MFA: %d %v", code, out)
	}
	e.accounts.mfa[4] = true
	if code, _ := e.do(t, nil, "POST", "/api/auth/recovery", `{"code": "0000-0000-0000-0000-0000"}`, ""); code != 401 {
		t.Fatalf("wrong code: %d", code)
	}
	code, out = e.do(t, nil, "POST", "/api/auth/recovery", `{"code": "`+codes[0].(string)+`"}`, "")
	if code != 200 || out["recovery_required"] != true || out["continuation"] != "/ssh/security" {
		t.Fatalf("recovery: %d %v", code, out)
	}
	if len(e.pending.completed) != 1 || e.pending.completed[0] != "4|recovery_code|MFA" {
		t.Fatalf("completed %v", e.pending.completed)
	}
	if code, _ := e.do(t, nil, "POST", "/api/auth/recovery", `{"code": "`+codes[0].(string)+`"}`, ""); code != 401 {
		t.Fatalf("reused code: %d", code)
	}
	e.pending.login.PrimaryMethod = "github"
	if code, _ := e.do(t, nil, "POST", "/api/auth/recovery", `{"code": "`+codes[1].(string)+`"}`, ""); code != 401 {
		t.Fatalf("provider sign-in: %d", code)
	}
	e.pending.err = errors.New("gone")
	if code, out := e.do(t, nil, "POST", "/api/auth/recovery", `{"code": "x"}`, ""); code != 401 || out["error"] != "Pending authentication is invalid" {
		t.Fatalf("no pending sign-in: %d %v", code, out)
	}
	e.limiter.limit = 0
	if code, out := e.do(t, nil, "POST", "/api/auth/recovery", `{"code": "x"}`, ""); code != 429 || out["code"] != "rate_limited" {
		t.Fatalf("rate limit: %d %v", code, out)
	}
}

func TestFactorRoutesFeatureGate(t *testing.T) {
	t.Parallel()
	e := newFactorEnv(t)
	e.h.MFA.Gates = fakeGates{}
	p := principaltest.User(1)
	for _, path := range []string{"/api/recovery-codes", "/api/auth/recovery", "/api/auth/mfa/disable"} {
		if code, _ := e.do(t, &p, "POST", path, `{}`, "ok"); code != 404 {
			t.Errorf("%s with recovery off: %d", path, code)
		}
	}
	if code, out := e.do(t, &p, "GET", "/api/account/security-state", ``, ""); code != 200 || out["total"] != float64(0) {
		t.Fatalf("security state: %d %v", code, out)
	}
}
