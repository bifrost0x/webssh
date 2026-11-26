package stepup

import (
	json "encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/auth"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/principal/principaltest"
)

type denyAfter struct {
	mu    sync.Mutex
	n     int
	limit int
}

func (d *denyAfter) Allow(string, auth.Rule) (bool, time.Duration) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.n++
	return d.n <= d.limit, 0
}

type httpEnv struct {
	*env
	mux     *http.ServeMux
	limiter *denyAfter
}

func newHTTPEnv(t *testing.T) *httpEnv {
	t.Helper()
	e := &httpEnv{env: newEnv(t), limiter: &denyAfter{limit: 1000}}
	h := &HTTP{Service: e.svc, Limits: auth.FactorLimits{Limiter: e.limiter, Enabled: true, Reauth: auth.Rule{Limit: 10, Window: time.Minute}}}
	e.mux = http.NewServeMux()
	h.Register(e.mux)
	return e
}

func (e *httpEnv) post(t *testing.T, p principal.Principal, path, body string) (int, map[string]any) {
	t.Helper()
	r := httptest.NewRequestWithContext(principal.With(t.Context(), p), "POST", path, strings.NewReader(body))
	w := httptest.NewRecorder()
	e.mux.ServeHTTP(w, r)
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("%s: %q: %v", path, w.Body.String(), err)
	}
	return w.Code, out
}

// The account family follows static/js/security-ui.js:createAccountStepUpClient.
func TestAccountFamily(t *testing.T) {
	t.Parallel()
	e := newHTTPEnv(t)
	p := principaltest.User(1)
	code, out := e.post(t, p, "/api/account/step-up/intents", `{"action":"host_key.delete","target":"abc"}`)
	if code != 200 || out["preferred_method"] != "password" || out["required_assurance"] != "BASIC" || out["expires_in"] != float64(300) {
		t.Fatalf("intent: %d %v", code, out)
	}
	intent := out["intent"].(string)
	if code, out := e.post(t, p, "/api/account/step-up/password", `{"intent":"`+intent+`","password":"nope"}`); code != 403 || out["code"] != "step_up_failed" {
		t.Fatalf("wrong password: %d %v", code, out)
	}
	code, out = e.post(t, p, "/api/account/step-up/password", `{"intent":"`+intent+`","password":"secret"}`)
	if code != 200 || out["method"] != "password" {
		t.Fatalf("password: %d %v", code, out)
	}
	if err := e.svc.Consume(t.Context(), p, principal.ActionHostKeyDelete, "abc", out["grant"].(string)); err != nil {
		t.Fatalf("grant from the account family: %v", err)
	}
	// Integer targets bind like their decimal form (TOTP and passkey ids).
	e.svc.Targets = nil
	code, out = e.post(t, p, "/api/account/step-up/intents", `{"action":"key.delete","target":42}`)
	if code != 200 {
		t.Fatalf("integer target: %d %v", code, out)
	}
	_, out = e.post(t, p, "/api/account/step-up/password", `{"intent":"`+out["intent"].(string)+`","password":"secret"}`)
	if err := e.svc.Consume(t.Context(), p, principal.ActionKeyDelete, "42", out["grant"].(string)); err != nil {
		t.Fatalf("integer target grant: %v", err)
	}
	for _, body := range []string{`{"action":"key.delete","target":true}`, `{"action":"key.delete","target":1.5}`, `{"action":"nope","target":"x"}`, `[]`, `{"action":"key.delete","target":""}`} {
		if code, out := e.post(t, p, "/api/account/step-up/intents", body); code != 400 || out["code"] != "invalid_request" {
			t.Errorf("%s: %d %v", body, code, out)
		}
	}
	e.limiter.limit = 0
	code, out = e.post(t, p, "/api/account/step-up/password", `{"intent":"x","password":"secret"}`)
	if code != 429 || out["retry_after"] != float64(60) {
		t.Fatalf("rate limit: %d %v", code, out)
	}
}

func TestAccountPasskey(t *testing.T) {
	t.Parallel()
	e := newHTTPEnv(t)
	p := principaltest.User(2)
	e.accounts.mfa[2], e.passkeys.enrolled[2] = true, true
	_, out := e.post(t, p, "/api/account/step-up/intents", `{"action":"key.upload","target":"new"}`)
	intent, _ := out["intent"].(string)
	if out["preferred_method"] != "passkey" {
		t.Fatalf("intent %v", out)
	}
	if code, out := e.post(t, p, "/api/account/step-up/passkey/options", `{"intent":"`+intent+`"}`); code != 200 || out["challenge"] != "abc" {
		t.Fatalf("options: %d %v", code, out)
	}
	if code, _ := e.post(t, p, "/api/account/step-up/passkey/verify", `{"intent":"`+intent+`","credential":{"id":"bad"}}`); code != 403 {
		t.Fatalf("bad assertion: %d", code)
	}
	code, out := e.post(t, p, "/api/account/step-up/passkey/verify", `{"intent":"`+intent+`","credential":{"id":"good"}}`)
	if code != 200 {
		t.Fatalf("assertion: %d %v", code, out)
	}
}

// The admin family follows static/js/admin.js:acquireStepUp.
func TestAdminFamily(t *testing.T) {
	t.Parallel()
	e := newHTTPEnv(t)
	user, admin := principaltest.User(3), principaltest.Admin(4)
	if code, _ := e.post(t, user, "/api/step-up/intents", `{"action":"user.create","target":"bob"}`); code != 403 {
		t.Fatalf("non-admin: %d", code)
	}
	code, out := e.post(t, admin, "/api/step-up/intents", `{"action":"security_feature.update","target":"totp"}`)
	if code != 200 || out["method"] != "password" {
		t.Fatalf("intent: %d %v", code, out)
	}
	// A wrong password is retryable: 403 invalid_value.
	code, out = e.post(t, admin, "/api/step-up/password", `{"action":"security_feature.update","target":"totp","password":"x"}`)
	if code != 403 || out["code"] != "invalid_value" {
		t.Fatalf("wrong password: %d %v", code, out)
	}
	code, out = e.post(t, admin, "/api/step-up/password", `{"action":"security_feature.update","target":"totp","password":"secret"}`)
	if code != 200 || out["expires_in"] != float64(300) {
		t.Fatalf("password: %d %v", code, out)
	}
	if err := e.svc.Consume(t.Context(), admin, principal.ActionSecurityFeatureUpdate, "totp", out["grant"].(string)); err != nil {
		t.Fatal(err)
	}
	// TOTP with MFA on.
	e.accounts.mfa[4], e.totp.enrolled[4] = true, true
	code, out = e.post(t, admin, "/api/step-up/totp", `{"action":"user.create","target":"bob","code":"123456"}`)
	if code != 200 {
		t.Fatalf("totp: %d %v", code, out)
	}
	if code, _ := e.post(t, admin, "/api/step-up/password", `{"action":"user.create","target":"bob","password":"secret"}`); code != 403 {
		t.Fatalf("password with MFA on: %d", code)
	}
	// Passkey: the verify call carries no intent; the newest admin intent of
	// the session is used.
	e.passkeys.enrolled[4] = true
	if code, out := e.post(t, admin, "/api/step-up/passkey/options", `{"action":"user.create","target":"bob"}`); code != 200 || out["challenge"] != "abc" {
		t.Fatalf("options: %d %v", code, out)
	}
	code, out = e.post(t, admin, "/api/step-up/passkey/verify", `{"credential":{"id":"good"}}`)
	if code != 200 {
		t.Fatalf("passkey: %d %v", code, out)
	}
	if err := e.svc.Consume(t.Context(), admin, principal.ActionUserCreate, "bob", out["grant"].(string)); err != nil {
		t.Fatal(err)
	}
	if code, _ := e.post(t, admin, "/api/step-up/passkey/verify", `{"credential":{"id":"good"}}`); code != 403 {
		t.Fatalf("second verify without options: %d", code)
	}
}
