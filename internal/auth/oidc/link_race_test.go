package oidc

import (
	"net/http"
	"testing"

	"github.com/bifrost0x/webssh/internal/auth"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/principal/principaltest"
)

// A lock that commits between the account check of the callback and the
// link must refuse the link (RS2-09).
func TestSelfLinkRefusesAccountLockedDuringLink(t *testing.T) {
	t.Parallel()
	x := newHarness(t, nil)
	alice := principaltest.User(1)
	x.stepUp.Issue(alice, principal.ActionOIDCSelfLink, "1", "g1")
	cb := x.redirect(t, authURLOf(t, x.do(t, "POST", "/api/account/oidc/link/start", "b", alice, "", auth.StepUpHeader, "g1")))
	x.accounts.mu.Lock()
	x.accounts.onTx = func(a *fakeAccounts) {
		acc, _ := a.OIDCAccount(t.Context(), 1)
		acc.Locked = true
		a.set(acc)
	}
	x.accounts.mu.Unlock()
	if w := x.do(t, "GET", cb, "b", alice, ""); w.Code != http.StatusForbidden {
		t.Fatalf("link of an account locked meanwhile: %d %s", w.Code, w.Body)
	}
	if _, err := x.h.Links.Account(t.Context(), auth.Identity{Issuer: x.f.srv.URL, Subject: "subject-1"}); err == nil {
		t.Fatal("identity linked to an account locked during the link")
	}
}
