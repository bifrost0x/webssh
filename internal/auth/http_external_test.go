package auth

import (
	"context"
	"net/http"
	"testing"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/store"
)

// externalRoutes adds test routes that call the flow as a provider
// package does.
func (e *env) externalRoutes(userID *int64, change func(context.Context, *store.Tx) error, got *error) {
	e.mux.HandleFunc("GET /test/external", func(w http.ResponseWriter, r *http.Request) {
		if err := e.flow.SignInExternal(w, r, *userID, "github", "/hosts"); err != nil {
			*got = err
			w.WriteHeader(http.StatusTeapot)
		}
	})
	e.mux.HandleFunc("POST /test/renew", func(w http.ResponseWriter, r *http.Request) {
		if err := e.flow.RenewAfter(w, r, principal.ReasonLogout, change); err != nil {
			*got = err
			w.WriteHeader(http.StatusTeapot)
		}
	})
}

func TestSignInExternal(t *testing.T) {
	t.Parallel()
	e := newEnv(t, true)
	acc := e.createUser(t, "alice", "password1")
	var uid = acc.ID
	var got error
	e.externalRoutes(&uid, nil, &got)
	b := e.browser()
	rec := b.do("GET", "/test/external", nil)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/hosts" {
		t.Fatalf("direct: %d %q %v", rec.Code, rec.Header().Get("Location"), got)
	}
	p := b.principal(t)
	sess, err := e.flow.Sessions.Lookup(t.Context(), p.SessionID)
	if err != nil || sess.PrimaryMethod != "github" || len(sess.Methods) != 1 || sess.Remember {
		t.Fatalf("session %+v %v", sess, err)
	}

	// With MFA the factor step follows; recovery codes are not offered.
	setMFA(t, e, uid, true)
	e.totp.enrolled[uid] = true
	e.flow.Factors = append(e.flow.Factors, fakeFactor{"recovery", map[int64]bool{uid: true}})
	b2 := e.browser()
	b2.do("GET", "/test/external", nil)
	if c := e.pages.last(); c.page != "login" || !c.login.MFARequired || c.login.AuthSource != "github" ||
		len(c.login.MFAMethods) != 1 || c.login.MFAMethods[0] != "totp" {
		t.Fatalf("factor step %+v", c)
	}
	if pu, err := e.flow.PendingUser(b2.request()); err != nil || pu != uid {
		t.Fatalf("pending %d %v", pu, err)
	}

	// Without a usable factor the sign-in is refused and nothing written.
	e.totp.enrolled[uid] = false
	got = nil
	if rec := e.browser().do("GET", "/test/external", nil); rec.Code != http.StatusTeapot || !fault.Is(got, fault.Forbidden) {
		t.Fatalf("no factor: %d %v", rec.Code, got)
	}
}

func TestRenewAfter(t *testing.T) {
	t.Parallel()
	e := newEnv(t, true)
	acc := e.createUser(t, "alice", "password1")
	uid := acc.ID
	var got error
	failing := false
	e.externalRoutes(&uid, func(context.Context, *store.Tx) error {
		if failing {
			return fault.New(fault.Conflict, "no")
		}
		return nil
	}, &got)
	b := e.browser()
	b.do("POST", "/login", creds("alice", "password1"))
	other := e.browser()
	other.do("POST", "/login", creds("alice", "password1"))
	before := b.principal(t)

	failing = true
	if rec := b.do("POST", "/test/renew", nil); rec.Code != http.StatusTeapot || !fault.Is(got, fault.Conflict) {
		t.Fatalf("failing change: %d %v", rec.Code, got)
	}
	if p := other.principal(t); p.SessionID == "" {
		t.Fatal("a failed change ended sessions")
	}
	failing = false
	if rec := b.do("POST", "/test/renew", nil); rec.Code != http.StatusOK {
		t.Fatalf("renew: %d %v", rec.Code, got)
	}
	after := b.principal(t)
	if after.SessionID == before.SessionID {
		t.Fatal("session not renewed")
	}
	if _, err := e.flow.Sessions.Authenticate(t.Context(), other.cookies["session"]); err == nil {
		t.Fatal("the other browser stays signed in")
	}
	a, _ := e.flow.Accounts.Get(t.Context(), uid)
	if a.AuthGeneration != acc.AuthGeneration+1 {
		t.Fatalf("generation %d", a.AuthGeneration)
	}
}

func setMFA(t *testing.T, e *env, uid int64, on bool) {
	t.Helper()
	if err := e.flow.DB.Write(t.Context(), func(tx *store.Tx) error {
		return e.flow.Accounts.SetMFARequiredTx(t.Context(), tx, uid, on)
	}); err != nil {
		t.Fatal(err)
	}
}

func (b *browser) request() *http.Request {
	r, _ := http.NewRequest("GET", "/", nil)
	for k, v := range b.cookies {
		r.AddCookie(&http.Cookie{Name: k, Value: v})
	}
	return r
}
