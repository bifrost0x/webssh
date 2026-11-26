package totp

import (
	json "encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/auth"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/principal/principaltest"
)

type httpEnv struct {
	*env
	mux     *http.ServeMux
	h       *HTTP
	stepUp  *grantStepUp
	pending *fakePending
}

func newHTTPEnv(t *testing.T) *httpEnv {
	t.Helper()
	e := &httpEnv{env: newEnv(t), stepUp: &grantStepUp{}, pending: &fakePending{}}
	e.h = &HTTP{Service: e.svc, Gates: e.svc.MFA.Gates, StepUp: e.stepUp, Pending: e.pending}
	e.mux = http.NewServeMux()
	e.h.Register(e.mux)
	return e
}

func (e *httpEnv) do(t *testing.T, p *principal.Principal, method, path, body, grant string) (int, map[string]any) {
	t.Helper()
	r := httptest.NewRequestWithContext(t.Context(), method, path, strings.NewReader(body))
	if p != nil {
		r = r.WithContext(principal.With(r.Context(), *p))
	}
	if grant != "" {
		r.Header.Set(auth.StepUpHeader, grant)
	}
	w := httptest.NewRecorder()
	e.mux.ServeHTTP(w, r)
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("%s %s: %q: %v", method, path, w.Body.String(), err)
	}
	return w.Code, out
}

func TestEnrolRoutes(t *testing.T) {
	t.Parallel()
	e := newHTTPEnv(t)
	p := principaltest.User(1)
	e.stepUp.action, e.stepUp.target = principal.ActionTOTPEnroll, "1"
	if code, out := e.do(t, &p, "POST", "/api/totp/enroll", `{"label":"Phone"}`, ""); code != 403 || out["code"] != "step_up_required" {
		t.Fatalf("enrol without grant: %d %v", code, out)
	}
	if code, _ := e.do(t, &p, "POST", "/api/totp/enroll", `{"label":"`+strings.Repeat("x", 81)+`"}`, "ok"); code != 400 {
		t.Fatalf("long label: %d", code)
	}
	code, out := e.do(t, &p, "POST", "/api/totp/enroll", `{"label":"Phone"}`, "ok")
	if code != 200 || out["token"] == nil || !strings.HasPrefix(out["qr_svg"].(string), "<?xml") {
		t.Fatalf("enrol: %d %v", code, out)
	}
	token, secret := out["token"].(string), out["secret"].(string)
	body := `{"token":"` + token + `","code":"` + e.codeAt(t, secret, 0) + `"}`
	if code, _ := e.do(t, &p, "POST", "/api/totp/enroll/verify", body, ""); code != 400 {
		t.Fatalf("unconfirmed activation: %d", code)
	}
	body = `{"token":"` + token + `","code":"` + e.codeAt(t, secret, 0) + `","confirm_enable_mfa":true}`
	code, out = e.do(t, &p, "POST", "/api/totp/enroll/verify", body, "")
	if codes, _ := out["recovery_codes"].([]any); code != 200 || len(codes) != 10 {
		t.Fatalf("activation: %d %v", code, out)
	}
	code, out = e.do(t, &p, "GET", "/api/totp/authenticators", ``, "")
	list, _ := out["authenticators"].([]any)
	if code != 200 || out["mfa_enabled"] != true || len(list) != 1 {
		t.Fatalf("list: %d %v", code, out)
	}
	first := list[0].(map[string]any)
	if first["label"] != "Phone" || first["last_used_at"] != nil || first["created_at"] != "2026-11-26T12:00:10" {
		t.Fatalf("entry %v", first)
	}
}

// A recovery session enrols without a grant and ends its restriction.
func TestRecoverySessionRepairsWithoutGrant(t *testing.T) {
	t.Parallel()
	e := newHTTPEnv(t)
	p := principaltest.User(2)
	p.Recovery = true
	e.accounts.mfa[2] = true
	code, out := e.do(t, &p, "POST", "/api/totp/enroll", `{}`, "")
	if code != 200 {
		t.Fatalf("recovery enrol: %d %v", code, out)
	}
	body := `{"token":"` + out["token"].(string) + `","code":"` + e.codeAt(t, out["secret"].(string), 0) + `","confirm_enable_mfa":true}`
	if code, out := e.do(t, &p, "POST", "/api/totp/enroll/verify", body, ""); code != 200 || len(out["recovery_codes"].([]any)) != 0 {
		t.Fatalf("recovery activation: %d %v", code, out)
	}
	if len(e.sessions.ended) != 1 || e.sessions.ended[0] != "session-2|totp|false" {
		t.Fatalf("recovery restriction: %v", e.sessions.ended)
	}
	if code, _ := e.do(t, &p, "DELETE", "/api/totp/authenticators/1", ``, "ok"); code != 403 {
		t.Fatalf("recovery session deleted a factor: %d", code)
	}
}

func TestDeleteRoute(t *testing.T) {
	t.Parallel()
	e := newHTTPEnv(t)
	p := principaltest.User(3)
	e.enrol(t, p)
	_, b := e.enrol(t, p)
	id := strconv.FormatInt(b.AuthenticatorID, 10)
	e.stepUp.action, e.stepUp.target = principal.ActionTOTPDelete, id
	other := principaltest.User(4)
	if code, _ := e.do(t, &other, "DELETE", "/api/totp/authenticators/"+id, ``, "ok"); code != 404 {
		t.Fatalf("foreign delete: %d", code)
	}
	for _, bad := range []string{"0", "-1", "01", "x"} {
		if code, _ := e.do(t, &p, "DELETE", "/api/totp/authenticators/"+bad, ``, "ok"); code != 404 {
			t.Errorf("id %q: %d", bad, code)
		}
	}
	if code, _ := e.do(t, &p, "DELETE", "/api/totp/authenticators/"+id, ``, "wrong"); code != 403 {
		t.Fatalf("delete without grant: %d", code)
	}
	if code, out := e.do(t, &p, "DELETE", "/api/totp/authenticators/"+id, ``, "ok"); code != 200 || out["mfa_enabled"] != true {
		t.Fatalf("delete: %d %v", code, out)
	}
}

func TestSignInRoute(t *testing.T) {
	t.Parallel()
	e := newHTTPEnv(t)
	secret, _ := e.enrol(t, principaltest.User(5))
	e.clock.Advance(time.Minute)
	e.pending.login = auth.PendingLogin{UserID: 5, PrimaryMethod: "password"}
	if code, out := e.do(t, nil, "POST", "/api/totp/auth/verify", `{"code":"`+e.codeAt(t, secret, 0)+`"}`, ""); code != 200 || out["continuation"] != "/next" {
		t.Fatalf("sign-in: %d %v", code, out)
	}
	e.clock.Advance(time.Hour)
	for i := 1; i <= 3; i++ {
		if code, out := e.do(t, nil, "POST", "/api/totp/auth/verify", `{"code":"000000"}`, ""); code != 401 || out["error"] != "TOTP code is invalid" {
			t.Fatalf("wrong code %d: %d %v", i, code, out)
		}
	}
	code, out := e.do(t, nil, "POST", "/api/totp/auth/verify", `{"code":"000000"}`, "")
	if code != 429 || out["code"] != "rate_limited" || out["retry_after"] != float64(30) {
		t.Fatalf("throttled: %d %v", code, out)
	}
	e.clock.Advance(30 * time.Second)
	e.do(t, nil, "POST", "/api/totp/auth/verify", `{"code":"000000"}`, "")
	e.clock.Advance(time.Minute)
	code, out = e.do(t, nil, "POST", "/api/totp/auth/verify", `{"code":"000000"}`, "")
	if out["code"] != "mfa_restart" || e.pending.discarded != 1 {
		t.Fatalf("fifth failure: %d %v (discarded %d)", code, out, e.pending.discarded)
	}
	if e.pending.completed != 1 {
		t.Fatalf("completed %d sign-ins", e.pending.completed)
	}
}

func TestRoutesFeatureGate(t *testing.T) {
	t.Parallel()
	e := newHTTPEnv(t)
	e.h.Gates = fakeGates{}
	p := principaltest.User(1)
	for _, path := range []string{"/api/totp/enroll", "/api/totp/enroll/verify", "/api/totp/auth/verify"} {
		if code, _ := e.do(t, &p, "POST", path, `{}`, "ok"); code != 404 {
			t.Errorf("%s with TOTP off: %d", path, code)
		}
	}
}
