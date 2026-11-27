package session

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// RS8-H20: the handle of another user's session is unknown to the
// session list: revoking it answers 404 and the session stays valid; a
// revocation of the other sessions leaves other users alone.
func TestRevokeOtherUsersSessionIsNotFound(t *testing.T) {
	t.Parallel()
	f := newFixture(t, nil)
	_, aliceTok := f.issue(t, 1, false)
	bobSess, bobTok := f.issue(t, 2, false)
	alice, _ := f.svc.Authenticate(t.Context(), aliceTok)
	h := &HTTP{Service: f.svc}
	mux := http.NewServeMux()
	h.Register(mux)
	post := func(body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, withPrincipal(httptest.NewRequest("POST", "/api/account/sessions/revoke", strings.NewReader(body)), alice))
		return rec
	}
	if rec := post(`{"session": "` + Handle(f.svc.mac, bobSess.ID) + `"}`); rec.Code != http.StatusNotFound {
		t.Fatalf("revoke another user's session: %d %s", rec.Code, rec.Body)
	}
	if rec := post(`{"others": true}`); rec.Code != http.StatusOK {
		t.Fatalf("revoke others: %d %s", rec.Code, rec.Body)
	}
	if _, err := f.svc.Authenticate(t.Context(), bobTok); err != nil {
		t.Fatalf("another user's session ended: %v", err)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, withPrincipal(httptest.NewRequest("GET", "/api/account/sessions", nil), alice))
	if strings.Contains(rec.Body.String(), Handle(f.svc.mac, bobSess.ID)) {
		t.Fatal("the session list shows another user's session")
	}
}
