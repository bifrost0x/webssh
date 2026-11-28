package accounts

import (
	"context"
	json "encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/principal/principaltest"
	"github.com/bifrost0x/webssh/internal/store"
	"github.com/bifrost0x/webssh/internal/store/storetest"
)

// fakeCredentials stores "hash:<password>" in a table of its own test
// schema-free map, so the tests do not depend on internal/auth/local.
type fakeCredentials struct {
	mu     sync.Mutex
	stored map[int64]string
	hashes atomic.Int32
}

func (f *fakeCredentials) ValidateNew(pw string) string {
	if len([]rune(pw)) < 8 {
		return "Password must be at least 8 characters"
	}
	return ""
}

func (f *fakeCredentials) Hash(_ context.Context, pw string) (string, error) {
	f.hashes.Add(1)
	return "hash:" + pw, nil
}

func (f *fakeCredentials) StoreTx(_ context.Context, _ *store.Tx, id int64, hash string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.stored == nil {
		f.stored = map[int64]string{}
	}
	f.stored[id] = hash
	return nil
}

type recordingAudit struct {
	mu     sync.Mutex
	events []string
}

func (a *recordingAudit) Security(event string, kv ...any) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, event)
}

func (a *recordingAudit) list() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.events...)
}

func newService(t *testing.T, admins ...string) (*Service, *recordingAudit) {
	t.Helper()
	audit := &recordingAudit{}
	return &Service{DB: storetest.Open(t, Schema()), Credentials: &fakeCredentials{}, Admins: admins, Audit: audit,
		Now: func() time.Time { return time.Date(2026, 11, 26, 9, 0, 0, 250000000, time.UTC) }}, audit
}

func insertLegacy(t *testing.T, s *Service, id int64, name string, admin, locked bool, managed Manager, incarnation string) {
	t.Helper()
	err := s.DB.Write(t.Context(), func(tx *store.Tx) error {
		_, err := tx.ExecContext(t.Context(), `INSERT INTO accounts_users (id, username, incarnation, history_generation, is_admin, is_locked, managed_by)
			VALUES (?, ?, ?, ?, ?, ?, ?)`, id, name, incarnation, "hist-"+name, admin, locked, string(managed))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

func code(err error) fault.Code { return fault.CodeOf(err) }

func message(err error) string {
	_, _, m := fault.Status(err)
	return m
}

func TestCreateFirstAccountIsAdmin(t *testing.T) {
	t.Parallel()
	s, audit := newService(t)
	a, err := s.Create(t.Context(), CreateRequest{Username: "admin", Password: "password1", FirstOnly: true})
	if err != nil || !a.IsAdmin || a.ID != 1 {
		t.Fatalf("%+v %v", a, err)
	}
	if a.Incarnation != "2026-11-26T09:00:00.250000" || a.HistoryGeneration != a.Incarnation {
		t.Fatalf("incarnation %q", a.Incarnation)
	}
	if got := audit.list(); len(got) != 1 || got[0] != "INITIAL_ADMIN_REGISTERED" {
		t.Fatalf("audit %v", got)
	}
	if _, err := s.Create(t.Context(), CreateRequest{Username: "second", Password: "password1", FirstOnly: true}); message(err) != "Registration is currently disabled." {
		t.Fatalf("bootstrap reopened: %v", err)
	}
	b, err := s.Create(t.Context(), CreateRequest{Username: "second", Password: "password1"})
	if err != nil || b.IsAdmin {
		t.Fatalf("%+v %v", b, err)
	}
	if has, _ := s.HasAccounts(t.Context()); !has {
		t.Fatal("HasAccounts false")
	}
}

func TestCreateValidation(t *testing.T) {
	t.Parallel()
	s, _ := newService(t, "Boss", "ghost")
	insertLegacy(t, s, 1, "Straße", true, false, ManagedLocal, "x")
	for _, c := range []struct {
		req  CreateRequest
		want string
	}{
		{CreateRequest{Username: "ab", Password: "password1"}, "Username must be between 3 and 32 characters"},
		{CreateRequest{Username: strings.Repeat("a", 33), Password: "password1"}, "Username must be between 3 and 32 characters"},
		{CreateRequest{Username: "jörg", Password: "password1"}, "Username can only contain letters, numbers, and underscores"},
		{CreateRequest{Username: "a b", Password: "password1"}, "Username can only contain letters, numbers, and underscores"},
		{CreateRequest{Username: "STRASSE", Password: "password1"}, "Username already exists"},
		{CreateRequest{Username: "boss", Password: "password1"}, "Username already exists"}, // reserved by ADMIN_USERS
		{CreateRequest{Username: "GHOST", Password: "password1"}, "Username already exists"},
		{CreateRequest{Username: "valid_1", Password: "short"}, "Password must be at least 8 characters"},
	} {
		_, err := s.Create(t.Context(), c.req)
		if code(err) != fault.InvalidValue || message(err) != c.want {
			t.Errorf("%+v: %v", c.req.Username, err)
		}
	}
	// An administrator may create a reserved name.
	if _, err := s.Create(t.Context(), CreateRequest{Username: "boss", Password: "password1", ByAdmin: true}); err != nil {
		t.Fatal(err)
	}
	if s.Credentials.(*fakeCredentials).hashes.Load() != 1 {
		t.Error("password hashed for a refused request")
	}
}

// The first account takes a reserved name too: it becomes admin anyway.
func TestFirstAccountMayTakeReservedName(t *testing.T) {
	t.Parallel()
	s, _ := newService(t, "root_admin")
	if a, err := s.Create(t.Context(), CreateRequest{Username: "root_admin", Password: "password1", FirstOnly: true}); err != nil || !a.IsAdmin {
		t.Fatalf("%+v %v", a, err)
	}
}

// Parallel bootstrap registrations produce exactly one account.
func TestBootstrapRace(t *testing.T) {
	t.Parallel()
	s, _ := newService(t)
	var wg sync.WaitGroup
	var ok atomic.Int32
	for i := range 16 {
		wg.Go(func() {
			_, err := s.Create(context.Background(), CreateRequest{Username: "user" + string(rune('a'+i)), Password: "password1", FirstOnly: true})
			if err == nil {
				ok.Add(1)
			} else if message(err) != "Registration is currently disabled." {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	all, _ := s.List(t.Context())
	if ok.Load() != 1 || len(all) != 1 || !all[0].IsAdmin {
		t.Fatalf("created %d, listed %d", ok.Load(), len(all))
	}
}

// Parallel registrations of one name with different case create one.
func TestNameRace(t *testing.T) {
	t.Parallel()
	s, _ := newService(t)
	insertLegacy(t, s, 1, "first", true, false, ManagedLocal, "x")
	var wg sync.WaitGroup
	for _, n := range []string{"Same", "same", "SAME", "sAme"} {
		wg.Go(func() { _, _ = s.Create(context.Background(), CreateRequest{Username: n, Password: "password1"}) })
	}
	wg.Wait()
	if all, _ := s.List(t.Context()); len(all) != 2 {
		t.Fatalf("%d accounts", len(all))
	}
}

func TestIDsAreNeverReused(t *testing.T) {
	t.Parallel()
	s, _ := newService(t)
	insertLegacy(t, s, 3, "legacy", true, false, ManagedLocal, "x")
	if err := s.DB.Write(t.Context(), func(tx *store.Tx) error { return s.RaiseIDFloorTx(t.Context(), tx, 12) }); err != nil {
		t.Fatal(err)
	}
	a, err := s.Create(t.Context(), CreateRequest{Username: "newbie", Password: "password1"})
	if err != nil || a.ID != 13 {
		t.Fatalf("id %d %v", a.ID, err)
	}
	// Removing the newest row must not hand its id out again.
	_ = s.DB.Write(t.Context(), func(tx *store.Tx) error {
		_, err := tx.ExecContext(t.Context(), `DELETE FROM accounts_users WHERE id = 13`)
		return err
	})
	b, _ := s.Create(t.Context(), CreateRequest{Username: "later", Password: "password1"})
	if b.ID != 14 {
		t.Fatalf("id reused: %d", b.ID)
	}
}

func TestStandingAndSignIn(t *testing.T) {
	t.Parallel()
	s, _ := newService(t)
	insertLegacy(t, s, 1, "alice", true, false, ManagedLocal, "x")
	insertLegacy(t, s, 2, "locked", false, true, ManagedLocal, "x")
	insertLegacy(t, s, 3, "dir", false, false, ManagedLDAP, "x")
	for name, want := range map[string]struct {
		id     int64
		usable bool
	}{"alice": {1, true}, "Alice": {0, false}, "locked": {2, false}, "dir": {3, false}, "none": {0, false}} {
		id, usable, err := s.SignInStanding(t.Context(), name)
		if err != nil || id != want.id || usable != want.usable {
			t.Errorf("%s: %d %v %v", name, id, usable, err)
		}
	}
	st, _ := s.Standing(t.Context(), 3)
	if !st.Exists || !st.Managed || st.Username != "dir" {
		t.Fatalf("%+v", st)
	}
	if st, err := s.Standing(t.Context(), 99); err != nil || st.Exists {
		t.Fatalf("missing: %+v %v", st, err)
	}
}

func TestPasswordChangedTx(t *testing.T) {
	t.Parallel()
	s, _ := newService(t)
	insertLegacy(t, s, 1, "modern", false, false, ManagedLocal, "hist-modern") // history == incarnation
	insertLegacy(t, s, 2, "nullcreated", false, false, ManagedLocal, "")       // history from hash
	for id, wantHist := range map[int64]string{1: "hist-modern", 2: "newhash"} {
		var gen int64
		err := s.DB.Write(t.Context(), func(tx *store.Tx) error {
			var err error
			gen, err = s.PasswordChangedTx(t.Context(), tx, id, "newhash")
			return err
		})
		a, _ := s.Get(t.Context(), id)
		if err != nil || gen != 1 || a.AuthGeneration != 1 || a.HistoryGeneration != wantHist {
			t.Errorf("%d: gen %d err %v %+v", id, gen, err, a)
		}
	}
}

func TestNormalize(t *testing.T) {
	t.Parallel()
	s, audit := newService(t, "listed", "LOCKEDLISTED", "locked_listed", "dir_listed", "missing")
	insertLegacy(t, s, 1, "dir_admin", true, false, ManagedLDAP, "x") // a managed admin does not count
	insertLegacy(t, s, 2, "oldest", false, false, ManagedLocal, "x")
	insertLegacy(t, s, 3, "listed", false, false, ManagedLocal, "x")
	insertLegacy(t, s, 4, "locked_listed", false, true, ManagedLocal, "x")
	insertLegacy(t, s, 5, "dir_listed", false, false, ManagedGitHub, "x")
	insertLegacy(t, s, 6, "Listed2", false, false, ManagedLocal, "x")
	if err := s.Normalize(t.Context()); err != nil {
		t.Fatal(err)
	}
	all, _ := s.List(t.Context())
	got := map[string]bool{}
	for _, a := range all {
		got[a.Username] = a.IsAdmin
	}
	want := map[string]bool{"dir_admin": true, "oldest": true, "listed": true, "locked_listed": false, "dir_listed": false, "Listed2": false}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s admin=%v, want %v", k, got[k], v)
		}
	}
	if ev := audit.list(); len(ev) != 1 || ev[0] != "INITIAL_ADMIN_REPAIRED" {
		t.Fatalf("audit %v", ev)
	}
	// Idempotent and never demotes.
	if err := s.Normalize(t.Context()); err != nil || len(audit.list()) != 1 {
		t.Fatalf("second run: %v %v", err, audit.list())
	}
}

func TestAdminRules(t *testing.T) {
	t.Parallel()
	s, _ := newService(t, "cfg", "dirlisted")
	cfg := Account{ID: 2, Username: "cfg", IsAdmin: true}
	plain := Account{ID: 3, Username: "plain", IsAdmin: true}
	if s.CheckDemote(2, cfg, 3) != ErrDemoteSelf || s.CheckDemote(1, plain, 1) != ErrDemoteLast ||
		s.CheckDemote(1, cfg, 3) != ErrDemoteManaged || s.CheckDemote(1, plain, 3) != nil {
		t.Fatal("demote rules")
	}
	if code(ErrDemoteManaged) != fault.Conflict || code(ErrConversion) != fault.Conflict {
		t.Fatal("variant B refusals must be 409")
	}
	// A locked listed admin is still managed (cannot be demoted).
	lockedCfg := cfg
	lockedCfg.IsLocked = true
	if s.CheckDemote(1, lockedCfg, 3) != ErrDemoteManaged {
		t.Fatal("locked listed admin demotable")
	}
	// Case differs: not managed by the exact start-up rule.
	if s.Admins.Manages(Account{Username: "CFG", IsAdmin: true}) {
		t.Fatal("Manages ignores case")
	}
	if s.CheckLocalConversion(Account{Username: "DirListed", Managed: ManagedLDAP}) != ErrConversion ||
		s.CheckLocalConversion(Account{Username: "other", Managed: ManagedGitHub}) != nil ||
		s.CheckLocalConversion(Account{Username: "cfg"}) != nil {
		t.Fatal("conversion rule")
	}
	if CheckPromote(Account{Managed: ManagedLDAP}) != ErrPromoteLDAP || CheckPromote(Account{Managed: ManagedGitHub}) != ErrPromoteGitHub || CheckPromote(Account{}) != nil {
		t.Fatal("promote rule")
	}
}

func TestFoldName(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{"Straße": "strasse", "ﬁle": "file", "ſam": "sam", "KELVIN": "kelvin", "Jörg": "jörg"} {
		if got := FoldName(in); got != want {
			t.Errorf("%s: %s", in, got)
		}
	}
}

func serveHTTP(t *testing.T, h *HTTP, p *principal.Principal, method, body, grant string) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	h.Register(mux)
	r := httptest.NewRequest(method, "/admin/api/users", strings.NewReader(body))
	if p != nil {
		r = r.WithContext(principal.With(r.Context(), *p))
	}
	if grant != "" {
		r.Header.Set(StepUpHeader, grant)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, r)
	return rec
}

func TestAdminHTTP(t *testing.T) {
	t.Parallel()
	s, audit := newService(t, "cfgadmin")
	insertLegacy(t, s, 1, "cfgadmin", true, false, ManagedLocal, "x")
	step := &principaltest.StepUp{}
	h := &HTTP{Accounts: s, StepUp: step, Enabled: true}
	admin := principaltest.Admin(1)
	user := principaltest.User(2)

	rec := serveHTTP(t, h, &admin, "GET", "", "")
	var list struct {
		Users []map[string]any `json:"users"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil || rec.Code != 200 || len(list.Users) != 1 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	u := list.Users[0]
	if u["admin_managed_by_config"] != true || u["created_at"] != nil || u["mfa_enabled"] != false || u["ldap_managed"] != false {
		t.Fatalf("user %v", u)
	}
	if rec := serveHTTP(t, h, &user, "GET", "", ""); rec.Code != 403 {
		t.Fatalf("non-admin %d", rec.Code)
	}
	if rec := serveHTTP(t, h, nil, "GET", "", ""); rec.Code != 401 {
		t.Fatalf("anonymous %d", rec.Code)
	}
	off := &HTTP{Accounts: s, StepUp: step}
	if rec := serveHTTP(t, off, &admin, "GET", "", ""); rec.Code != 404 {
		t.Fatalf("disabled panel %d", rec.Code)
	}

	body := `{"username": " newadmin ", "password": "password1", "is_admin": true}`
	if rec := serveHTTP(t, h, &admin, "POST", body, "g1"); rec.Code != 403 || !strings.Contains(rec.Body.String(), "step_up_required") {
		t.Fatalf("without grant %d %s", rec.Code, rec.Body)
	}
	step.Issue(admin, principal.ActionUserCreate, "newadmin", "g1")
	rec = serveHTTP(t, h, &admin, "POST", body, "g1")
	if rec.Code != 201 || !strings.Contains(rec.Body.String(), `"username":"newadmin"`) || !strings.Contains(rec.Body.String(), `"is_admin":true`) {
		t.Fatalf("create %d %s", rec.Code, rec.Body)
	}
	if ev := audit.list(); len(ev) == 0 || ev[len(ev)-1] != "ADMIN_USER_CREATED" {
		t.Fatalf("audit %v", ev)
	}
	// Replaying the grant fails.
	if rec := serveHTTP(t, h, &admin, "POST", body, "g1"); rec.Code != 403 {
		t.Fatalf("replay %d", rec.Code)
	}
	for _, bad := range []string{`not json`, `{"username": null, "password": "password1"}`, `{"username": "abc", "password": 5}`, `{"username": "abc", "password": "password1", "is_admin": "yes"}`} {
		target := "invalid-payload"
		if strings.Contains(bad, `"abc"`) {
			target = "abc"
		}
		step.Issue(admin, principal.ActionUserCreate, target, "g2")
		if rec := serveHTTP(t, h, &admin, "POST", bad, "g2"); rec.Code != 400 || !strings.Contains(rec.Body.String(), "Invalid user payload") {
			t.Errorf("%s: %d %s", bad, rec.Code, rec.Body)
		}
	}
	step.Issue(admin, principal.ActionUserCreate, "x", "g3")
	if rec := serveHTTP(t, h, &admin, "POST", `{"username": "x", "password": "password1"}`, "g3"); rec.Code != 400 || !strings.Contains(rec.Body.String(), "between 3 and 32") {
		t.Fatalf("validation %d %s", rec.Code, rec.Body)
	}
}

func TestPromote(t *testing.T) {
	t.Parallel()
	s, _ := newService(t)
	insertLegacy(t, s, 1, "admin", true, false, ManagedLocal, "2026-01-01T00:00:00")
	insertLegacy(t, s, 2, "user", false, true, ManagedLocal, "2026-01-01T00:00:00")
	insertLegacy(t, s, 3, "dir", false, false, ManagedLDAP, "2026-01-01T00:00:00")
	insertLegacy(t, s, 4, "gh", false, false, ManagedGitHub, "2026-01-01T00:00:00")
	if changed, err := s.Promote(t.Context(), 1); changed || err != nil {
		t.Errorf("already admin: %v, %v", changed, err)
	}
	if changed, err := s.Promote(t.Context(), 2); !changed || err != nil {
		t.Errorf("promote: %v, %v", changed, err)
	}
	if a, _ := s.Get(t.Context(), 2); !a.IsAdmin {
		t.Error("not promoted")
	}
	if _, err := s.Promote(t.Context(), 3); err != ErrPromoteLDAP {
		t.Errorf("ldap: %v", err)
	}
	if _, err := s.Promote(t.Context(), 4); err != ErrPromoteGitHub {
		t.Errorf("github: %v", err)
	}
	if _, err := s.Promote(t.Context(), 9); code(err) != fault.NotFound {
		t.Errorf("missing: %v", err)
	}
	if a, _ := s.Get(t.Context(), 3); a.IsAdmin {
		t.Error("ldap account promoted")
	}
}

// NotFirst refuses the first account inside the write transaction: a
// registration through a host that may not create it cannot win the race
// with an account removal or the first registration (finding #68).
func TestCreateNotFirstRefusesTheFirstAccount(t *testing.T) {
	t.Parallel()
	s, audit := newService(t)
	if _, err := s.Create(t.Context(), CreateRequest{Username: "rebind", Password: "password1", NotFirst: true}); !fault.Is(err, fault.Forbidden) {
		t.Fatalf("first account with NotFirst: %v", err)
	}
	if has, _ := s.HasAccounts(t.Context()); has || len(audit.list()) != 0 {
		t.Fatal("an account was created")
	}
	if _, err := s.Create(t.Context(), CreateRequest{Username: "admin", Password: "password1"}); err != nil {
		t.Fatal(err)
	}
	if b, err := s.Create(t.Context(), CreateRequest{Username: "second", Password: "password1", NotFirst: true}); err != nil || b.IsAdmin {
		t.Fatalf("%+v %v", b, err)
	}
}
