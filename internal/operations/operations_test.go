package operations

import (
	"bytes"
	"context"
	json "encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/principal/principaltest"
	"github.com/bifrost0x/webssh/internal/store/storetest"
)

type inventory struct {
	mu       sync.Mutex
	accounts []Account
}

func (i *inventory) Accounts(context.Context) ([]Account, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	return append([]Account(nil), i.accounts...), nil
}
func (i *inventory) GitHubActive(context.Context) (bool, error) { return false, nil }

type auditLog struct{ events []string }

func (a *auditLog) Security(e string, kv ...any) { a.events = append(a.events, e) }

func newGates(t *testing.T) *Gates {
	t.Helper()
	return &Gates{
		DB:         storetest.Open(t, Schema()),
		Deployment: map[string]bool{"passkey": true, "totp": true, "oidc": true, "ldap": false, "recovery": true},
		Ready: map[string]Readiness{"passkey": {Ready: true}, "totp": {Ready: true}, "recovery": {Ready: true},
			"oidc": {Reason: "OIDC provider discovery failed."}},
		Audit: &auditLog{},
	}
}

func TestStatusRules(t *testing.T) {
	t.Parallel()
	g := newGates(t)
	all, err := g.All(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]struct {
		active bool
		reason string
	}{
		"passkey":  {true, ""},
		"totp":     {false, "TOTP is not activated in the admin panel."}, // no upgrade default
		"oidc":     {false, "OIDC provider discovery failed."},
		"ldap":     {false, "LDAP is disabled by deployment configuration."},
		"recovery": {true, ""},
	}
	for _, s := range all {
		w := want[s.Name]
		reason := ""
		if s.Reason != nil {
			reason = *s.Reason
		}
		if s.Active != w.active || reason != w.reason {
			t.Errorf("%s: active=%v reason=%q", s.Name, s.Active, reason)
		}
	}
	if _, err := g.Status(t.Context(), " TOTP "); err != nil {
		t.Fatal("name not normalised")
	}
	if _, err := g.Status(t.Context(), "github"); err == nil {
		t.Fatal("unknown feature accepted")
	}
	if ok, _ := g.Active(t.Context(), "unknown"); ok {
		t.Fatal("unknown feature active")
	}
}

func TestSetRespectsCeiling(t *testing.T) {
	t.Parallel()
	g := newGates(t)
	admin := principaltest.Admin(1)
	s, err := g.set(t.Context(), admin, "totp", true)
	if err != nil || !s.Active {
		t.Fatalf("%+v %v", s, err)
	}
	if _, err := g.set(t.Context(), admin, "ldap", true); err == nil {
		t.Fatal("enabled beyond the deployment ceiling")
	}
	if _, err := g.set(t.Context(), admin, "oidc", true); err == nil {
		t.Fatal("enabled a feature that is not ready")
	}
	// Disabling is always possible and survives a later deployment change.
	if s, _ := g.set(t.Context(), admin, "passkey", false); s.Active || s.AdminEnabled {
		t.Fatalf("%+v", s)
	}
	if ev := g.Audit.(*auditLog).events; len(ev) != 2 {
		t.Fatalf("audit %v", ev)
	}
}

func mac(t *testing.T) *keyring.Ring {
	t.Helper()
	r, err := keyring.Open([]byte("s"), bytes.Repeat([]byte{3}, keyring.MaterialSize))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestImpactCounts(t *testing.T) {
	t.Parallel()
	g := newGates(t)
	inv := &inventory{accounts: []Account{
		{ID: 1, Username: "admin", Admin: true, Password: true, Passkey: []Credential{{1, "t"}}},
		{ID: 2, Username: "pk_only", MFA: true, Passkey: []Credential{{2, "t"}}},
		{ID: 3, Username: "locked", Locked: true, Passkey: []Credential{{3, "t"}}},
		{ID: 4, Username: "plain", Password: true},
	}}
	_, im, err := g.snapshot(t.Context(), inv, "passkey")
	if err != nil {
		t.Fatal(err)
	}
	if im.AffectedAccounts != 3 || im.AffectedAdmins != 1 || im.LockedAffectedAccounts != 1 ||
		im.AccountsWithoutPrimary != 1 || im.MFARequiredWithoutLocalFactor != 1 || im.RemainingPrimary["password"] != 1 {
		t.Fatalf("%+v", im)
	}
	if im.Accounts[1].Username != "pk_only" || len(im.Accounts[1].RemainingPrimary) != 0 {
		t.Fatalf("%+v", im.Accounts[1])
	}
}

func serve(t *testing.T, h *HTTP, p principal.Principal, method, path, body, grant string) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	h.Register(mux)
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r = r.WithContext(principal.With(r.Context(), p))
	if grant != "" {
		r.Header.Set(StepUpHeader, grant)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, r)
	return rec
}

func TestDisableNeedsConfirmationAndFreshApproval(t *testing.T) {
	t.Parallel()
	g := newGates(t)
	inv := &inventory{accounts: []Account{{ID: 1, Username: "admin", Admin: true, Password: true}}}
	step := &principaltest.StepUp{}
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	h := &HTTP{Gates: g, Inventory: inv, StepUp: step, MAC: mac(t), Enabled: true, Now: func() time.Time { return now }}
	admin := principaltest.Admin(1)

	if rec := serve(t, h, admin, "GET", "/admin/api/security-features", "", ""); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"configuration_keys":["WEBAUTHN_ENABLED"`) {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if rec := serve(t, h, principaltest.User(2), "GET", "/admin/api/security-features", "", ""); rec.Code != 403 {
		t.Fatalf("non-admin %d", rec.Code)
	}
	if rec := serve(t, h, admin, "POST", "/admin/api/security-features/passkey", `{"enabled": false}`, "g"); rec.Code != 403 {
		t.Fatalf("no step-up %d", rec.Code)
	}
	grant := func(g string) string {
		step.Issue(admin, principal.ActionSecurityFeatureUpdate, "passkey", g)
		return g
	}
	rec := serve(t, h, admin, "POST", "/admin/api/security-features/passkey", `{"enabled": false}`, grant("g1"))
	if rec.Code != 409 || !strings.Contains(rec.Body.String(), "session_fallback_confirmation_required") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	rec = serve(t, h, admin, "GET", "/admin/api/security-features/passkey/impact", "", "")
	var preview struct {
		Approval string `json:"approval"`
		Impact   Impact `json:"impact"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &preview); err != nil || preview.Approval == "" || preview.Impact.Feature != "passkey" {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	body := `{"enabled": false, "confirm_session_fallback": true, "impact_approval": "` + preview.Approval + `"}`
	// The state changed after the preview: refused.
	inv.mu.Lock()
	inv.accounts = append(inv.accounts, Account{ID: 2, Username: "new", Password: true})
	inv.mu.Unlock()
	if rec := serve(t, h, admin, "POST", "/admin/api/security-features/passkey", body, grant("g2")); rec.Code != 409 || !strings.Contains(rec.Body.String(), "feature_impact_changed") {
		t.Fatalf("changed state: %d %s", rec.Code, rec.Body)
	}
	rec = serve(t, h, admin, "GET", "/admin/api/security-features/passkey/impact", "", "")
	_ = json.Unmarshal(rec.Body.Bytes(), &preview)
	body = `{"enabled": false, "confirm_session_fallback": true, "impact_approval": "` + preview.Approval + `"}`
	// Another session of the same admin cannot use the approval.
	other := admin
	other.SessionID = "other"
	step.Issue(other, principal.ActionSecurityFeatureUpdate, "passkey", "g3")
	if rec := serve(t, h, other, "POST", "/admin/api/security-features/passkey", body, "g3"); rec.Code != 409 {
		t.Fatalf("other session: %d", rec.Code)
	}
	// Expired.
	now = now.Add(6 * time.Minute)
	if rec := serve(t, h, admin, "POST", "/admin/api/security-features/passkey", body, grant("g4")); rec.Code != 409 {
		t.Fatalf("expired: %d", rec.Code)
	}
	now = now.Add(-6 * time.Minute)
	if rec := serve(t, h, admin, "POST", "/admin/api/security-features/passkey", body, grant("g5")); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"active":false`) {
		t.Fatalf("disable: %d %s", rec.Code, rec.Body)
	}
	// Enabling a feature beyond the ceiling: 409 with the reason.
	step.Issue(admin, principal.ActionSecurityFeatureUpdate, "ldap", "g6")
	if rec := serve(t, h, admin, "POST", "/admin/api/security-features/ldap", `{"enabled": true}`, "g6"); rec.Code != 409 || !strings.Contains(rec.Body.String(), "disabled by deployment configuration") {
		t.Fatalf("ceiling: %d %s", rec.Code, rec.Body)
	}
	step.Issue(admin, principal.ActionSecurityFeatureUpdate, "totp", "g7")
	if rec := serve(t, h, admin, "POST", "/admin/api/security-features/totp", `{"enabled": "yes"}`, "g7"); rec.Code != 400 {
		t.Fatalf("bad body: %d", rec.Code)
	}
	step.Issue(admin, principal.ActionSecurityFeatureUpdate, "nope", "g8")
	if rec := serve(t, h, admin, "POST", "/admin/api/security-features/nope", `{"enabled": true}`, "g8"); rec.Code != 404 {
		t.Fatalf("unknown: %d", rec.Code)
	}
	off := *h
	off.Enabled = false
	if rec := serve(t, &off, admin, "GET", "/admin/api/security-features", "", ""); rec.Code != 404 {
		t.Fatalf("panel off: %d", rec.Code)
	}
}

// Disable, re-enable and the old approval no longer disables again.
func TestApprovalNotReusableAfterReenable(t *testing.T) {
	t.Parallel()
	g := newGates(t)
	tick := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	g.Now = func() time.Time { tick = tick.Add(time.Second); return tick }
	inv := &inventory{}
	admin := principaltest.Admin(1)
	_, _ = g.set(t.Context(), admin, "passkey", true)
	d1, _, err := g.snapshot(t.Context(), inv, "passkey")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = g.set(t.Context(), admin, "passkey", false)
	_, _ = g.set(t.Context(), admin, "passkey", true)
	d2, _, _ := g.snapshot(t.Context(), inv, "passkey")
	if d1 == d2 {
		t.Fatal("digest unchanged after disable and re-enable")
	}
}

func FuzzApproval(f *testing.F) {
	f.Add("v1.1764158400.00")
	f.Add("v1..")
	r, _ := keyring.Open([]byte("s"), bytes.Repeat([]byte{3}, keyring.MaterialSize))
	p := principaltest.Admin(1)
	now := time.Unix(1764158400, 0)
	good := approval(r, "totp", p, now, "d")
	f.Fuzz(func(t *testing.T, token string) {
		if approvalValid(r, token, "totp", p, now, "d") && token != good {
			t.Fatalf("forged approval accepted: %q", token)
		}
	})
}
