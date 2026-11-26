package github

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/auth"
	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/store"
	"github.com/bifrost0x/webssh/internal/store/storetest"
)

// fakeGitHub is a test double of the GitHub endpoints WebSSH calls, with
// the semantics of tests/lab/github-stub: codes bound to redirect URI and
// PKCE challenge, one use each.
type fakeGitHub struct {
	srv          *httptest.Server
	clientID     string
	clientSecret string

	mu      sync.Mutex
	users   map[string]fakeUser
	codes   map[string]fakeCode
	tokens  map[string]string
	flaky   map[string]bool
	profile func() (int, string) // overrides GET /user
	calls   map[string]int
}

type fakeUser struct {
	ID   int64
	Name string
	Orgs map[string]string
}

type fakeCode struct{ login, redirect, challenge string }

func newFakeGitHub(t *testing.T) *fakeGitHub {
	g := &fakeGitHub{clientID: "webssh-test-client", clientSecret: "test-client-secret-0123456789",
		users: map[string]fakeUser{
			"octo-alice": {ID: 1001, Name: "Alice", Orgs: map[string]string{"lab-org": "active"}},
			"octo-bob":   {ID: 1002, Orgs: map[string]string{"lab-org": "pending"}},
			"octo-carol": {ID: 1003, Orgs: map[string]string{}},
		},
		codes: map[string]fakeCode{}, tokens: map[string]string{}, flaky: map[string]bool{"flaky-org": true}, calls: map[string]int{}}
	g.srv = httptest.NewTLSServer(http.HandlerFunc(g.serve))
	t.Cleanup(g.srv.Close)
	return g
}

// issue makes a code for login as the authorize step would.
func (g *fakeGitHub) issue(login, redirect, challenge string) string {
	g.mu.Lock()
	defer g.mu.Unlock()
	code := "code-" + strconv.Itoa(len(g.codes)+1) + "-" + login
	g.codes[code] = fakeCode{login, redirect, challenge}
	return code
}

func (g *fakeGitHub) writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (g *fakeGitHub) serve(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.calls[r.URL.Path]++
	if r.URL.Path == "/login/oauth/access_token" {
		_ = r.ParseForm()
		f := r.PostForm
		if f.Get("client_id") != g.clientID || subtle.ConstantTimeCompare([]byte(f.Get("client_secret")), []byte(g.clientSecret)) != 1 {
			g.writeJSON(w, 200, map[string]string{"error": "incorrect_client_credentials"})
			return
		}
		c, ok := g.codes[f.Get("code")]
		delete(g.codes, f.Get("code"))
		sum := sha256.Sum256([]byte(f.Get("code_verifier")))
		if !ok || c.redirect != f.Get("redirect_uri") || base64.RawURLEncoding.EncodeToString(sum[:]) != c.challenge {
			g.writeJSON(w, 200, map[string]string{"error": "bad_verification_code"})
			return
		}
		token := "gho_" + strconv.Itoa(len(g.tokens)+1)
		g.tokens[token] = c.login
		g.writeJSON(w, 200, map[string]string{"access_token": token, "token_type": "bearer"})
		return
	}
	login, ok := g.tokens[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
	if !ok || r.Header.Get("X-GitHub-Api-Version") != apiVersion {
		g.writeJSON(w, 401, map[string]string{"message": "Bad credentials"})
		return
	}
	u := g.users[login]
	if r.URL.Path == "/user" {
		if g.profile != nil {
			status, body := g.profile()
			w.WriteHeader(status)
			_, _ = w.Write([]byte(body))
			return
		}
		body := map[string]any{"id": u.ID, "login": login, "name": nil}
		if u.Name != "" {
			body["name"] = u.Name
		}
		g.writeJSON(w, 200, body)
		return
	}
	if org, ok := strings.CutPrefix(r.URL.Path, "/user/memberships/orgs/"); ok {
		switch state, member := u.Orgs[org]; {
		case g.flaky[org]:
			g.writeJSON(w, 502, map[string]string{"message": "Server Error"})
		case !member:
			g.writeJSON(w, 404, map[string]string{"message": "Not Found"})
		default:
			g.writeJSON(w, 200, map[string]string{"state": state})
		}
		return
	}
	g.writeJSON(w, 404, map[string]string{"message": "Not Found"})
}

func (g *fakeGitHub) client() Client {
	return Client{WebURL: g.srv.URL, APIURL: g.srv.URL, HTTP: g.srv.Client()}
}

// fakeAccounts keeps accounts in memory with the name rules of
// internal/accounts.
type fakeAccounts struct {
	mu       sync.Mutex
	accounts map[int64]*Account
	next     int64
	released []int64
}

var fakeNameRule = regexp.MustCompile(`^[A-Za-z0-9_]{3,32}$`)

func (a *fakeAccounts) add(name, managed string) int64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.next++
	a.accounts[a.next] = &Account{ID: a.next, Username: name, Managed: managed}
	return a.next
}

func (a *fakeAccounts) get(id int64) Account {
	a.mu.Lock()
	defer a.mu.Unlock()
	return *a.accounts[id]
}

func (a *fakeAccounts) update(id int64, fn func(*Account)) {
	a.mu.Lock()
	defer a.mu.Unlock()
	fn(a.accounts[id])
}

func (a *fakeAccounts) AccountTx(_ context.Context, _ *store.Tx, id int64) (Account, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	acc, ok := a.accounts[id]
	if !ok {
		return Account{}, fault.New(fault.NotFound, "")
	}
	return *acc, nil
}

func (a *fakeAccounts) ProvisionTx(_ context.Context, _ *store.Tx, name, manager string) (int64, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !fakeNameRule.MatchString(name) {
		return 0, fault.New(fault.InvalidValue, "")
	}
	for _, acc := range a.accounts {
		if strings.EqualFold(acc.Username, name) {
			return 0, fault.New(fault.Conflict, "")
		}
	}
	a.next++
	a.accounts[a.next] = &Account{ID: a.next, Username: name, Managed: manager}
	return a.next, nil
}

func (a *fakeAccounts) ReleaseTx(_ context.Context, _ *store.Tx, id int64, _ string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.accounts[id].Managed = ""
	a.released = append(a.released, id)
	return nil
}

// fakeSignIn records sign-ins and renewals.
type fakeSignIn struct {
	db      *store.DB
	mu      sync.Mutex
	signed  []int64
	renewed int
	noMFA   bool
}

func (f *fakeSignIn) SignInExternal(w http.ResponseWriter, r *http.Request, in auth.ExternalSignIn) error {
	if f.noMFA {
		return fault.New(fault.Forbidden, "")
	}
	f.mu.Lock()
	f.signed = append(f.signed, in.UserID)
	f.mu.Unlock()
	http.Redirect(w, r, auth.PublicContinuation("", in.Continuation), http.StatusFound)
	return nil
}

func (f *fakeSignIn) RenewAfter(_ http.ResponseWriter, r *http.Request, _ principal.Reason, change func(context.Context, *store.Tx) error) error {
	err := f.db.Write(r.Context(), func(tx *store.Tx) error { return change(r.Context(), tx) })
	if err == nil {
		f.mu.Lock()
		f.renewed++
		f.mu.Unlock()
	}
	return err
}

// fakeStepUp accepts the grant "grant:<action>:<target>".
type fakeStepUp struct{}

func (fakeStepUp) Consume(_ context.Context, _ principal.Principal, action principal.Action, target, grant string) error {
	if grant != "grant:"+string(action)+":"+target {
		return fault.New(fault.StepUpRequired, "")
	}
	return nil
}

type fakePasskeys map[int64]int

func (p fakePasskeys) Count(_ context.Context, _ *store.Tx, id int64) (int, error) { return p[id], nil }

type fakeAdmins []string

func (a fakeAdmins) Reserves(name string) bool {
	for _, n := range a {
		if strings.EqualFold(n, name) {
			return true
		}
	}
	return false
}

type env struct {
	t        *testing.T
	svc      *Service
	gh       *fakeGitHub
	accounts *fakeAccounts
	signIn   *fakeSignIn
	passkeys fakePasskeys
	mux      *http.ServeMux
	now      time.Time
}

const testRedirect = "https://ssh.example.test/auth/github/callback"

func newEnv(t *testing.T) *env {
	t.Helper()
	ring, err := keyring.Open([]byte("test-secret"), make([]byte, keyring.MaterialSize))
	if err != nil {
		t.Fatal(err)
	}
	db := storetest.Open(t, Schema())
	e := &env{t: t, gh: newFakeGitHub(t), accounts: &fakeAccounts{accounts: map[int64]*Account{}},
		passkeys: fakePasskeys{}, now: time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC)}
	e.signIn = &fakeSignIn{db: db}
	e.svc = &Service{DB: db, Ring: ring, Accounts: e.accounts, SignIn: e.signIn, StepUp: fakeStepUp{},
		Passkeys: e.passkeys, Admins: fakeAdmins{"cfgadmin"}, Client: e.gh.client(),
		Binding: func(r *http.Request) string { return r.Header.Get("X-Test-Binding") },
		Now:     func() time.Time { return e.now }}
	e.mux = http.NewServeMux()
	e.svc.Register(e.mux)
	return e
}

// configure stores an active configuration through the update route's
// service call.
func (e *env) configure(extra map[string]any) {
	e.t.Helper()
	body := map[string]any{"enabled": true, "client_id": e.gh.clientID, "client_secret": e.gh.clientSecret, "redirect_uri": testRedirect}
	maps.Copy(body, extra)
	raw, _ := json.Marshal(body)
	if _, err := e.svc.Update(e.t.Context(), raw, 1); err != nil {
		e.t.Fatalf("configure: %v", err)
	}
}

// do sends a request through the mux, as principal p when p is valid.
func (e *env) do(method, target, binding string, p principal.Principal, header map[string]string, body string) *httptest.ResponseRecorder {
	e.t.Helper()
	req := httptest.NewRequestWithContext(e.t.Context(), method, target, strings.NewReader(body))
	req.Header.Set("X-Test-Binding", binding)
	for k, v := range header {
		req.Header.Set(k, v)
	}
	if p.Valid() {
		req = req.WithContext(principal.With(req.Context(), p))
	}
	rec := httptest.NewRecorder()
	e.mux.ServeHTTP(rec, req)
	return rec
}

// authorize starts a redirect and lets the fake GitHub sign in login; it
// returns the callback URL path with query.
func (e *env) authorize(start *httptest.ResponseRecorder, login string) string {
	e.t.Helper()
	var target string
	if loc := start.Header().Get("Location"); loc != "" {
		target = loc
	} else {
		var body map[string]string
		if err := json.Unmarshal(start.Body.Bytes(), &body); err != nil {
			e.t.Fatalf("start: %d %s", start.Code, start.Body)
		}
		target = body["authorization_url"]
	}
	u, err := url.Parse(target)
	if err != nil || !strings.HasSuffix(u.Path, "/login/oauth/authorize") {
		e.t.Fatalf("authorization URL %q (%d %s)", target, start.Code, start.Body)
	}
	q := u.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("redirect_uri") != testRedirect || q.Get("client_id") != e.gh.clientID {
		e.t.Fatalf("authorization query %v", q)
	}
	code := e.gh.issue(login, q.Get("redirect_uri"), q.Get("code_challenge"))
	return "/auth/github/callback?" + url.Values{"code": {code}, "state": {q.Get("state")}}.Encode()
}

func decode(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("body %q: %v", rec.Body, err)
	}
	return m
}
