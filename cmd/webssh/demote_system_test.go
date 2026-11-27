package main

import (
	"net/http"
	"strings"
	"testing"

	"github.com/bifrost0x/webssh/internal/accounts"
	"github.com/bifrost0x/webssh/internal/store"
)

// RS8-R01 through the server: a demoted administrator loses the
// administration at the next request and the administrator grants it
// already held, keeps its session and its ordinary rights.
func TestDemotionEndsAdministratorRightsAtOnce(t *testing.T) {
	sys, ts := openTestSystem(t, map[string]string{"ADMIN_PANEL_ENABLED": "true"})
	admin := signUp(t, ts.URL, "admin1", "first-password-1")
	bobAcc, err := sys.accounts.Create(t.Context(), accounts.CreateRequest{Username: "bob", Password: "bob-password-1", ByAdmin: true, Admin: true})
	if err != nil {
		t.Fatal(err)
	}
	bob := signIn(t, ts.URL, "bob", "bob-password-1")
	if resp, _ := get(t, bob, ts.URL+"/admin/api/users"); resp.StatusCode != http.StatusOK {
		t.Fatalf("bob is no administrator before: %d", resp.StatusCode)
	}
	adminGrant(t, bob, ts.URL, "user.manage", "1:lock", "bob-password-1")
	countGrants := func() int {
		var n int
		err := sys.db.Read(t.Context(), func(tx *store.Tx) error {
			return tx.QueryRowContext(t.Context(), `SELECT count(*) FROM stepup_grants WHERE user_id = ?`, bobAcc.ID).Scan(&n)
		})
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	if countGrants() != 1 {
		t.Fatal("bob holds no administrator grant")
	}

	grant := adminGrant(t, admin, ts.URL, "user.manage", "2:demote", "first-password-1")
	if status, body := apiCall(t, admin, ts.URL, http.MethodPost, "/admin/api/users/2/demote", nil, grant); status != http.StatusOK || !strings.Contains(body, `"is_admin":false`) {
		t.Fatalf("demote: %d %s", status, body)
	}
	if resp, _ := get(t, bob, ts.URL+"/admin/api/users"); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("the administration after the demotion: %d", resp.StatusCode)
	}
	if n := countGrants(); n != 0 {
		t.Fatalf("%d administrator grants survived the demotion", n)
	}
	if resp, _ := get(t, bob, ts.URL+"/api/account/sessions"); resp.StatusCode != http.StatusOK {
		t.Fatalf("the demoted account lost its session: %d", resp.StatusCode)
	}
	if list, _ := sys.sessions.List(t.Context(), bobAcc.ID); len(list) != 1 {
		t.Fatalf("%d sessions after the demotion", len(list))
	}
}
