package oidc

import (
	"context"
	json "encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/auth"
	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/principal/principaltest"
	"github.com/bifrost0x/webssh/internal/store"
	"github.com/bifrost0x/webssh/internal/store/storetest"
)

type fakeAccounts struct {
	mu   sync.Mutex
	m    map[int64]Account
	onTx func(*fakeAccounts)
}

func (a *fakeAccounts) OIDCAccount(_ context.Context, id int64) (Account, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	acc, ok := a.m[id]
	if !ok {
		return Account{}, fault.New(fault.NotFound, "")
	}
	return acc, nil
}

// OIDCAccountTx reads the account, and lets a test change it between the
// first check and the transaction (onTx).
func (a *fakeAccounts) OIDCAccountTx(ctx context.Context, _ *store.Tx, id int64) (Account, error) {
	a.mu.Lock()
	hook := a.onTx
	a.mu.Unlock()
	if hook != nil {
		hook(a)
	}
	return a.OIDCAccount(ctx, id)
}

func (a *fakeAccounts) set(acc Account) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.m[acc.ID] = acc
}

type fakeSignIn struct {
	mu      sync.Mutex
	last    *auth.ExternalSignIn
	renewed []principal.Reason
	db      *store.DB
}

func (s *fakeSignIn) RenewAfter(w http.ResponseWriter, r *http.Request, reason principal.Reason, change func(ctx context.Context, tx *store.Tx) error) error {
	s.mu.Lock()
	s.renewed = append(s.renewed, reason)
	s.mu.Unlock()
	return s.db.Write(r.Context(), func(tx *store.Tx) error { return change(r.Context(), tx) })
}

func (s *fakeSignIn) SignInExternal(w http.ResponseWriter, r *http.Request, in auth.ExternalSignIn) error {
	s.mu.Lock()
	s.last = &in
	s.mu.Unlock()
	http.Redirect(w, r, in.Continuation, http.StatusFound)
	return nil
}

// fakeProofs completes intents named "intent-<n>" for the session that
// began them.
type fakeProofs struct {
	mu       sync.Mutex
	required auth.Assurance
	proven   map[string]auth.Assurance
	begun    int
}

func (f *fakeProofs) BeginExternal(_ context.Context, p principal.Principal, action principal.Action, target, method string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.begun++
	return "admin-intent:" + p.SessionID + ":" + string(action) + ":" + target, nil
}

func (f *fakeProofs) ExternalIntent(_ context.Context, p principal.Principal, intent, method string) (auth.Assurance, error) {
	if !strings.HasPrefix(intent, "intent-") || method != "oidc" {
		return "", fault.New(fault.StepUpFailed, "")
	}
	return f.required, nil
}

func (f *fakeProofs) ProveExternal(_ context.Context, p principal.Principal, intent, method string, level auth.Assurance) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.proven == nil {
		f.proven = map[string]auth.Assurance{}
	}
	if _, done := f.proven[intent]; done {
		return "", fault.New(fault.StepUpFailed, "")
	}
	f.proven[intent] = level
	return "grant-for-" + intent, nil
}

type fakeSessions struct {
	mu      sync.Mutex
	revoked []string
}

func (s *fakeSessions) InvalidateTx(_ context.Context, _ *store.Tx, userID int64, reason principal.Reason) ([]principal.Revocation, error) {
	return []principal.Revocation{{UserID: userID, Reason: reason}}, nil
}

func (s *fakeSessions) Publish(revs []principal.Revocation) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range revs {
		s.revoked = append(s.revoked, string(r.Reason))
	}
}

type harness struct {
	f        *fakeIdP
	h        *HTTP
	mux      *http.ServeMux
	accounts *fakeAccounts
	signIn   *fakeSignIn
	proofs   *fakeProofs
	sessions *fakeSessions
	stepUp   *principaltest.StepUp
}

func newHarness(t *testing.T, change func(*Settings)) *harness {
	t.Helper()
	f := newFakeIdP(t)
	s := f.settings(nil)
	if change != nil {
		change(&s)
	}
	x := &harness{f: f, accounts: &fakeAccounts{m: map[int64]Account{}}, signIn: &fakeSignIn{}, proofs: &fakeProofs{required: auth.AssuranceBasic},
		sessions: &fakeSessions{}, stepUp: &principaltest.StepUp{}}
	db := storetest.Open(t, Schema())
	x.signIn.db = db
	x.h = &HTTP{Provider: newTestProvider(t, s), Links: &Links{DB: db}, Flights: &auth.Flights{},
		SignIn: x.signIn, Accounts: x.accounts, StepUp: x.stepUp, Proofs: x.proofs, Sessions: x.sessions,
		Binding: func(r *http.Request) string {
			if c, err := r.Cookie("binding"); err == nil {
				return c.Value
			}
			return ""
		}}
	x.mux = http.NewServeMux()
	x.h.Register(x.mux)
	x.accounts.set(Account{ID: 1, Username: "alice", Generation: 3})
	x.accounts.set(Account{ID: 2, Username: "admin", Generation: 1})
	return x
}

// do sends a request as browser with principal p (zero for none).
func (x *harness) do(t *testing.T, method, target, browser string, p principal.Principal, body string, header ...string) *httptest.ResponseRecorder {
	t.Helper()
	ctx := t.Context()
	if p.Valid() {
		ctx = principal.With(ctx, p)
	}
	r := httptest.NewRequestWithContext(ctx, method, target, strings.NewReader(body))
	r.AddCookie(&http.Cookie{Name: "binding", Value: browser})
	for i := 0; i+1 < len(header); i += 2 {
		r.Header.Set(header[i], header[i+1])
	}
	w := httptest.NewRecorder()
	x.mux.ServeHTTP(w, r)
	return w
}

// redirect follows an authorization URL at the fake provider and returns
// the callback path WebSSH receives.
func (x *harness) redirect(t *testing.T, authURL string) string {
	t.Helper()
	code, q := x.f.authorize(t, authURL)
	return "/oidc/callback?" + url.Values{"code": {code}, "state": {q.Get("state")}}.Encode()
}

func authURLOf(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	if w.Code == http.StatusFound {
		return w.Header().Get("Location")
	}
	var body struct {
		URL string `json:"authorization_url"`
	}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &body) != nil || body.URL == "" {
		t.Fatalf("no authorization URL: %d %s", w.Code, w.Body)
	}
	return body.URL
}

func (x *harness) link(t *testing.T, userID int64, subject string) int64 {
	t.Helper()
	li, err := x.h.Links.Link(t.Context(), userID, auth.Identity{Issuer: x.h.Provider.Issuer(), Subject: subject})
	if err != nil {
		t.Fatal(err)
	}
	return li.ID
}

func TestSignInRoute(t *testing.T) {
	t.Parallel()
	x := newHarness(t, nil)
	x.link(t, 1, "subject-1")
	w := x.do(t, "GET", "/oidc/login?next=/files", "b1", principal.Principal{}, "")
	cb := x.redirect(t, authURLOf(t, w))
	// The state belongs to browser b1 only.
	if w := x.do(t, "GET", cb, "b2", principal.Principal{}, ""); w.Code != http.StatusBadRequest {
		t.Fatalf("callback in another browser: %d %s", w.Code, w.Body)
	}
	if w := x.do(t, "GET", cb, "b1", principal.Principal{}, ""); w.Code != http.StatusFound || w.Header().Get("Location") != "/files" {
		t.Fatalf("callback: %d %s", w.Code, w.Body)
	}
	if in := x.signIn.last; in == nil || in.UserID != 1 || in.Method != "oidc" || in.Assurance != auth.AssuranceBasic {
		t.Fatalf("sign-in %+v", in)
	}
	// A replayed callback finds no flight.
	if w := x.do(t, "GET", cb, "b1", principal.Principal{}, ""); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), msgInvalidLogin) {
		t.Fatalf("replay: %d %s", w.Code, w.Body)
	}
	if w := x.do(t, "GET", "/oidc/callback?state=a&state=b&code=c", "b1", principal.Principal{}, ""); w.Code != http.StatusBadRequest {
		t.Fatalf("repeated state: %d", w.Code)
	}
}

func TestSignInRefusals(t *testing.T) {
	t.Parallel()
	for name, c := range map[string]struct {
		acc  *Account
		link bool
	}{
		"unlinked":     {nil, false},
		"locked":       {&Account{ID: 1, Username: "alice", Locked: true}, true},
		"LDAP-managed": {&Account{ID: 1, Username: "alice", Managed: "ldap"}, true},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			x := newHarness(t, nil)
			if c.link {
				x.link(t, 1, "subject-1")
			}
			if c.acc != nil {
				x.accounts.set(*c.acc)
			}
			cb := x.redirect(t, authURLOf(t, x.do(t, "GET", "/oidc/login", "b", principal.Principal{}, "")))
			if w := x.do(t, "GET", cb, "b", principal.Principal{}, ""); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), msgNotLinked) {
				t.Fatalf("%d %s", w.Code, w.Body)
			}
			if x.signIn.last != nil {
				t.Fatal("signed in")
			}
		})
	}
	t.Run("provider error parameter", func(t *testing.T) {
		t.Parallel()
		x := newHarness(t, nil)
		x.link(t, 1, "subject-1")
		_, q := x.f.authorize(t, authURLOf(t, x.do(t, "GET", "/oidc/login", "b", principal.Principal{}, "")))
		if w := x.do(t, "GET", "/oidc/callback?error=access_denied&state="+q.Get("state"), "b", principal.Principal{}, ""); w.Code != http.StatusBadRequest {
			t.Fatalf("%d", w.Code)
		}
	})
	t.Run("provider down", func(t *testing.T) {
		t.Parallel()
		x := newHarness(t, nil)
		x.f.srv.Close()
		if w := x.do(t, "GET", "/oidc/login", "b", principal.Principal{}, ""); w.Code != http.StatusServiceUnavailable {
			t.Fatalf("%d %s", w.Code, w.Body)
		}
	})
}

func TestSelfLink(t *testing.T) {
	t.Parallel()
	x := newHarness(t, nil)
	alice := principaltest.User(1)
	x.stepUp.Issue(alice, principal.ActionOIDCSelfLink, "1", "g1")
	if w := x.do(t, "POST", "/api/account/oidc/link/start", "b", alice, ""); w.Code == http.StatusOK {
		t.Fatal("link start without step-up grant")
	}
	x.stepUp.Issue(alice, principal.ActionOIDCSelfLink, "1", "g2")
	w := x.do(t, "POST", "/api/account/oidc/link/start", "b", alice, "", auth.StepUpHeader, "g2")
	u := authURLOf(t, w)
	if q, _ := url.Parse(u); q.Query().Get("prompt") != "login" {
		t.Fatalf("link does not ask to authenticate again: %s", u)
	}
	cb := x.redirect(t, u)
	// Another session of the same browser cannot complete the link.
	other := alice
	other.SessionID = "other"
	if w := x.do(t, "GET", cb, "b", other, ""); w.Code != http.StatusForbidden {
		t.Fatalf("other session: %d", w.Code)
	}
	x.stepUp.Issue(alice, principal.ActionOIDCSelfLink, "1", "g3")
	cb = x.redirect(t, authURLOf(t, x.do(t, "POST", "/api/account/oidc/link/start", "b", alice, "", auth.StepUpHeader, "g3")))
	if w := x.do(t, "GET", cb, "b", alice, ""); w.Code != http.StatusFound || w.Header().Get("Location") != "/settings" {
		t.Fatalf("link: %d %s", w.Code, w.Body)
	}
	w = x.do(t, "GET", "/api/account/oidc", "b", alice, "")
	if !strings.Contains(w.Body.String(), `"issuer":"`+x.f.srv.URL+`"`) || strings.Contains(w.Body.String(), "subject") {
		t.Fatalf("status: %s", w.Body)
	}
	// The identity cannot move to another account.
	x.accounts.set(Account{ID: 5, Username: "eve", Generation: 1})
	eve := principaltest.User(5)
	x.stepUp.Issue(eve, principal.ActionOIDCSelfLink, "5", "g4")
	cb = x.redirect(t, authURLOf(t, x.do(t, "POST", "/api/account/oidc/link/start", "b5", eve, "", auth.StepUpHeader, "g4")))
	if w := x.do(t, "GET", cb, "b5", eve, ""); w.Code != http.StatusConflict {
		t.Fatalf("second account: %d %s", w.Code, w.Body)
	}
	if id, _ := x.h.Links.Account(t.Context(), auth.Identity{Issuer: x.f.srv.URL, Subject: "subject-1"}); id != 1 {
		t.Fatalf("identity moved to %d", id)
	}
}

func TestSelfLinkBindings(t *testing.T) {
	t.Parallel()
	x := newHarness(t, nil)
	alice := principaltest.User(1)
	x.stepUp.Issue(alice, principal.ActionOIDCSelfLink, "1", "g")
	cb := x.redirect(t, authURLOf(t, x.do(t, "POST", "/api/account/oidc/link/start", "b", alice, "", auth.StepUpHeader, "g")))
	// A password change in between raised the generation.
	x.accounts.set(Account{ID: 1, Username: "alice", Generation: 4})
	if w := x.do(t, "GET", cb, "b", alice, ""); w.Code != http.StatusForbidden {
		t.Fatalf("changed generation: %d", w.Code)
	}
	if n := x.f.tokenHits.Load(); n != 0 {
		t.Fatalf("code redeemed for a refused link: %d", n)
	}
	for name, acc := range map[string]Account{"LDAP": {ID: 1, Username: "alice", Generation: 4, Managed: "ldap"}, "GitHub": {ID: 1, Username: "alice", Generation: 4, Managed: "github"}} {
		x.accounts.set(acc)
		x.stepUp.Issue(alice, principal.ActionOIDCSelfLink, "1", "g-"+name)
		if w := x.do(t, "POST", "/api/account/oidc/link/start", "b", alice, "", auth.StepUpHeader, "g-"+name); w.Code != http.StatusConflict {
			t.Fatalf("%s-managed: %d", name, w.Code)
		}
	}
}

func TestAdminStepUp(t *testing.T) {
	t.Parallel()
	now := time.Now().Unix()
	x := newHarness(t, func(s *Settings) {
		s.Assurance = AssurancePolicy{MFAAMR: []string{"otp"}}
		s.StepUpACR = []string{"urn:mfa"}
	})
	admin := principaltest.Admin(2)
	x.link(t, 2, "subject-1")
	start := func() string {
		w := x.do(t, "POST", "/api/step-up/oidc/start", "b", admin, `{"action":"user.manage","target":"1:lock"}`)
		u := authURLOf(t, w)
		if q, _ := url.Parse(u); q.Query().Get("max_age") != "0" || q.Query().Get("acr_values") != "urn:mfa" {
			t.Fatalf("step-up request %s", u)
		}
		return x.redirect(t, u)
	}
	if w := x.do(t, "GET", "/api/step-up/oidc/result", "b", admin, ""); w.Code != http.StatusNotFound {
		t.Fatalf("result before step-up: %d", w.Code)
	}
	// A BASIC provider answer does not confirm an administrator.
	x.f.set(map[string]any{"auth_time": now, "acr": "urn:mfa"})
	if w := x.do(t, "GET", start(), "b", admin, ""); w.Code != http.StatusForbidden {
		t.Fatalf("BASIC answer: %d", w.Code)
	}
	// The wrong acr does not either.
	x.f.set(map[string]any{"amr": []string{"otp"}, "acr": "urn:other"})
	if w := x.do(t, "GET", start(), "b", admin, ""); w.Code != http.StatusForbidden {
		t.Fatalf("wrong acr: %d", w.Code)
	}
	x.f.set(map[string]any{"acr": "urn:mfa"})
	if w := x.do(t, "GET", start(), "b", admin, ""); w.Code != http.StatusFound || w.Header().Get("Location") != "/admin" {
		t.Fatalf("step-up: %d %s", w.Code, w.Body)
	}
	w := x.do(t, "GET", "/api/step-up/oidc/result", "b", admin, "")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"action":"user.manage"`) || !strings.Contains(w.Body.String(), "grant-for-admin-intent:") {
		t.Fatalf("result: %d %s", w.Code, w.Body)
	}
	if w := x.do(t, "GET", "/api/step-up/oidc/result", "b", admin, ""); w.Code != http.StatusNotFound {
		t.Fatalf("result twice: %d", w.Code)
	}
	// A non-administrator cannot start or finish it.
	if w := x.do(t, "POST", "/api/step-up/oidc/start", "b", principaltest.User(1), `{"action":"user.manage","target":"1:lock"}`); w.Code == http.StatusOK {
		t.Fatal("user started an administrator step-up")
	}
	if w := x.do(t, "POST", "/api/step-up/oidc/start", "b", admin, `{"action":"nope","target":"x"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("unknown action: %d", w.Code)
	}
}

func TestAccountStepUp(t *testing.T) {
	t.Parallel()
	x := newHarness(t, func(s *Settings) { s.StepUpACR = []string{"urn:mfa"} })
	alice := principaltest.User(1)
	x.link(t, 1, "subject-1")
	x.f.set(map[string]any{"auth_time": time.Now().Unix()})
	w := x.do(t, "POST", "/api/account/step-up/oidc/start", "b", alice, `{"intent":"intent-1"}`)
	u := authURLOf(t, w)
	if strings.Contains(u, "acr_values") {
		t.Fatalf("BASIC intent asks for acr: %s", u)
	}
	if w := x.do(t, "GET", x.redirect(t, u), "b", alice, ""); w.Code != http.StatusFound || w.Header().Get("Location") != "/settings" {
		t.Fatalf("callback: %d %s", w.Code, w.Body)
	}
	if x.proofs.proven["intent-1"] != auth.AssuranceBasic {
		t.Fatalf("proofs %v", x.proofs.proven)
	}
	// An identity of another account does not prove alice.
	x.link(t, 5, "subject-2")
	x.accounts.set(Account{ID: 5, Username: "eve"})
	x.f.set(map[string]any{"sub": "subject-2"})
	w = x.do(t, "POST", "/api/account/step-up/oidc/start", "b", alice, `{"intent":"intent-2"}`)
	if w := x.do(t, "GET", x.redirect(t, authURLOf(t, w)), "b", alice, ""); w.Code != http.StatusForbidden {
		t.Fatalf("foreign identity: %d", w.Code)
	}
	// An old authentication at the provider is no step-up.
	x.f.set(map[string]any{"sub": "subject-1", "auth_time": time.Now().Add(-10 * time.Minute).Unix()})
	w = x.do(t, "POST", "/api/account/step-up/oidc/start", "b", alice, `{"intent":"intent-3"}`)
	if w := x.do(t, "GET", x.redirect(t, authURLOf(t, w)), "b", alice, ""); w.Code != http.StatusForbidden {
		t.Fatalf("old auth_time: %d", w.Code)
	}
	if w := x.do(t, "POST", "/api/account/step-up/oidc/start", "b", alice, `{"intent":"bogus"}`); w.Code != http.StatusForbidden {
		t.Fatalf("unknown intent: %d", w.Code)
	}
	x.proofs.required = auth.AssuranceMFA
	if u := authURLOf(t, x.do(t, "POST", "/api/account/step-up/oidc/start", "b", alice, `{"intent":"intent-4"}`)); !strings.Contains(u, "acr_values=urn%3Amfa") {
		t.Fatalf("MFA intent does not ask for acr: %s", u)
	}
}

func TestAdminIdentityRoutes(t *testing.T) {
	t.Parallel()
	x := newHarness(t, nil)
	admin := principaltest.Admin(2)
	if w := x.do(t, "POST", "/admin/api/users/1/oidc-link", "b", admin, `{"subject":"s-1","confirm_username":"alice"}`); w.Code == http.StatusCreated {
		t.Fatal("linked without step-up")
	}
	x.stepUp.Issue(admin, principal.ActionOIDCLink, "1", "g1")
	if w := x.do(t, "POST", "/admin/api/users/1/oidc-link", "b", admin, `{"subject":" s-1 ","confirm_username":"bob"}`, auth.StepUpHeader, "g1"); w.Code != http.StatusBadRequest {
		t.Fatalf("wrong confirmation: %d", w.Code)
	}
	x.stepUp.Issue(admin, principal.ActionOIDCLink, "1", "g2")
	w := x.do(t, "POST", "/admin/api/users/1/oidc-link", "b", admin, `{"subject":" s-1 ","confirm_username":"alice"}`, auth.StepUpHeader, "g2")
	if w.Code != http.StatusCreated {
		t.Fatalf("link: %d %s", w.Code, w.Body)
	}
	x.stepUp.Issue(admin, principal.ActionOIDCLink, "1", "g3")
	if w := x.do(t, "POST", "/admin/api/users/1/oidc-link", "b", admin, `{"subject":"s-1","confirm_username":"alice"}`, auth.StepUpHeader, "g3"); w.Code != http.StatusConflict {
		t.Fatalf("duplicate: %d", w.Code)
	}
	w = x.do(t, "GET", "/admin/api/users/1/oidc-identities", "b", admin, "")
	var list struct {
		Identities []identityJSON `json:"identities"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil || len(list.Identities) != 1 || list.Identities[0].Subject != "s-1" ||
		list.Identities[0].Issuer != x.f.srv.URL {
		t.Fatalf("list: %s %v", w.Body, err)
	}
	if w := x.do(t, "GET", "/admin/api/users/99/oidc-identities", "b", admin, ""); w.Code != http.StatusNotFound {
		t.Fatalf("unknown user: %d", w.Code)
	}
	id := list.Identities[0].ID
	target := "1:" + strconvItoa(id)
	x.stepUp.Issue(admin, principal.ActionOIDCUnlink, target, "g4")
	if w := x.do(t, "DELETE", "/admin/api/users/1/oidc-identities/"+strconvItoa(id), "b", admin, `{"confirm_username":"alice"}`, auth.StepUpHeader, "g4"); w.Code != http.StatusOK {
		t.Fatalf("unlink: %d %s", w.Code, w.Body)
	}
	if len(x.sessions.revoked) != 1 {
		t.Fatalf("sessions of the unlinked identity not ended: %v", x.sessions.revoked)
	}
	x.stepUp.Issue(admin, principal.ActionOIDCUnlink, target, "g5")
	if w := x.do(t, "DELETE", "/admin/api/users/1/oidc-identities/"+strconvItoa(id), "b", admin, `{"confirm_username":"alice"}`, auth.StepUpHeader, "g5"); w.Code != http.StatusNotFound {
		t.Fatalf("unlink twice: %d", w.Code)
	}
	x.accounts.set(Account{ID: 3, Username: "dir", Managed: "ldap"})
	x.stepUp.Issue(admin, principal.ActionOIDCLink, "3", "g6")
	if w := x.do(t, "POST", "/admin/api/users/3/oidc-link", "b", admin, `{"subject":"s","confirm_username":"dir"}`, auth.StepUpHeader, "g6"); w.Code != http.StatusBadRequest {
		t.Fatalf("managed account: %d", w.Code)
	}
	if w := x.do(t, "GET", "/admin/api/users/1/oidc-identities", "b", principaltest.User(1), ""); w.Code == http.StatusOK {
		t.Fatal("user listed identities")
	}
	if w := x.do(t, "GET", "/admin/api/users/01/oidc-identities", "b", admin, ""); w.Code != http.StatusNotFound {
		t.Fatalf("leading zero: %d", w.Code)
	}
}

func strconvItoa(n int64) string { return strconv.FormatInt(n, 10) }

// An administrator unlinking an own identity keeps this browser through
// the session renewal with the reason logout; nothing is revoked apart.
func TestAdminUnlinksOwnIdentity(t *testing.T) {
	t.Parallel()
	x := newHarness(t, nil)
	admin := principaltest.Admin(2)
	x.accounts.set(Account{ID: 2, Username: "root"})
	x.stepUp.Issue(admin, principal.ActionOIDCLink, "2", "g1")
	if w := x.do(t, "POST", "/admin/api/users/2/oidc-link", "b", admin, `{"subject":"s-2","confirm_username":"root"}`, auth.StepUpHeader, "g1"); w.Code != http.StatusCreated {
		t.Fatalf("link: %d %s", w.Code, w.Body)
	}
	w := x.do(t, "GET", "/admin/api/users/2/oidc-identities", "b", admin, "")
	var list struct {
		Identities []identityJSON `json:"identities"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil || len(list.Identities) != 1 {
		t.Fatalf("list: %s %v", w.Body, err)
	}
	id := strconvItoa(list.Identities[0].ID)
	x.stepUp.Issue(admin, principal.ActionOIDCUnlink, "2:"+id, "g2")
	if w := x.do(t, "DELETE", "/admin/api/users/2/oidc-identities/"+id, "b", admin, `{"confirm_username":"root"}`, auth.StepUpHeader, "g2"); w.Code != http.StatusOK {
		t.Fatalf("unlink: %d %s", w.Code, w.Body)
	}
	if len(x.signIn.renewed) != 1 || x.signIn.renewed[0] != principal.ReasonLogout || len(x.sessions.revoked) != 0 {
		t.Fatalf("renewed %v, revoked %v", x.signIn.renewed, x.sessions.revoked)
	}
}
