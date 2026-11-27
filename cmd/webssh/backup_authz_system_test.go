package main

import (
	json "encoding/json/v2"
	"net/http"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/accounts"
)

// RS8-H41: the backup routes refuse an account that is not an
// administrator, an administrator without a grant, another administrator
// and another session of the same administrator; the operation stays
// usable for the session that started it.
func TestBackupRoutesAuthorization(t *testing.T) {
	sys, ts := openTestSystem(t, map[string]string{
		"ADMIN_PANEL_ENABLED": "true", "BACKUP_TEMP_DIR": t.TempDir(), "RATELIMIT_ENABLED": "false",
	})
	const pw = "admin-password-1"
	admin := signUp(t, ts.URL, "admin1", pw)
	if _, err := sys.accounts.Create(t.Context(), accounts.CreateRequest{Username: "bob", Password: "bob-password-1", ByAdmin: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := sys.accounts.Create(t.Context(), accounts.CreateRequest{Username: "carol", Password: "carol-password-1", ByAdmin: true, Admin: true}); err != nil {
		t.Fatal(err)
	}
	bob := signIn(t, ts.URL, "bob", "bob-password-1")
	carol := signIn(t, ts.URL, "carol", "carol-password-1")
	admin2 := signIn(t, ts.URL, "admin1", pw)

	status, body := apiCall(t, admin, ts.URL, http.MethodPost, "/admin/api/backups", nil, adminGrant(t, admin, ts.URL, "backup.create", "new", pw))
	var created struct {
		ID string `json:"operation_id"`
	}
	if status != http.StatusAccepted || json.Unmarshal([]byte(body), &created) != nil || created.ID == "" {
		t.Fatalf("create: %d %s", status, body)
	}
	id := created.ID
	backupReady(t, admin, ts.URL, id)

	type call struct {
		method, path, action, target string
		body                         any
	}
	calls := []call{
		{http.MethodGet, "/admin/api/backups/" + id, "", "", nil},
		{http.MethodPost, "/admin/api/backups/" + id + "/download", "backup.download", id, nil},
		{http.MethodPost, "/admin/api/backups/" + id + "/cancel", "backup.cancel", id, nil},
		{http.MethodPost, "/admin/api/backups/" + id + "/restore/prepare", "backup.restore_prepare", id, map[string]any{"acknowledge_sensitive_restore": true}},
		{http.MethodPost, "/admin/api/backups/" + id + "/restore", "backup.restore", id,
			map[string]any{"confirmation_token": "guess", "confirmation_phrase": "RESTORE", "confirm_destructive_restore": true}},
	}
	send := func(c *http.Client, k call, grant string) (int, string) {
		if k.method == http.MethodGet {
			resp, body := get(t, c, ts.URL+k.path)
			return resp.StatusCode, body
		}
		return apiCall(t, c, ts.URL, k.method, k.path, k.body, grant)
	}

	// Not an administrator: refused at the edge, whatever the route.
	for _, k := range append(calls, call{http.MethodPost, "/admin/api/backups", "", "", nil}, call{http.MethodGet, "/admin/api/backups/restore/status", "", "", nil}) {
		if status, body := send(bob, k, "x"); status != http.StatusForbidden {
			t.Errorf("bob %s %s: %d %s", k.method, k.path, status, body)
		}
	}
	// The owner without a grant: a step-up is required.
	for _, k := range calls[1:] {
		if status, body := send(admin, k, ""); status != http.StatusForbidden {
			t.Errorf("no grant %s: %d %s", k.path, status, body)
		}
	}
	// Another administrator and another session of the owner, each with
	// a valid grant of its own: the operation does not exist for them.
	for name, c := range map[string]*http.Client{"carol": carol, "second session": admin2} {
		password := pw
		if name == "carol" {
			password = "carol-password-1"
		}
		for _, k := range calls {
			grant := ""
			if k.action != "" {
				grant = adminGrant(t, c, ts.URL, k.action, k.target, password)
			}
			if status, body := send(c, k, grant); status != http.StatusNotFound {
				t.Errorf("%s %s: %d %s", name, k.path, status, body)
			}
		}
	}
	// Unchanged for its own session.
	backupReady(t, admin, ts.URL, id)
	if status, _ := apiCall(t, admin, ts.URL, http.MethodPost, "/admin/api/backups/"+id+"/download", nil, adminGrant(t, admin, ts.URL, "backup.download", id, pw)); status != http.StatusOK {
		t.Fatalf("the owner's download after the refusals: %d", status)
	}
}

func backupReady(t *testing.T, c *http.Client, base, id string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		resp, body := get(t, c, base+"/admin/api/backups/"+id)
		var st struct {
			Status string `json:"status"`
		}
		if resp.StatusCode != http.StatusOK || json.Unmarshal([]byte(body), &st) != nil {
			t.Fatalf("status: %d %s", resp.StatusCode, body)
		}
		switch st.Status {
		case "ready":
			return
		case "failed":
			t.Fatalf("backup failed: %s", body)
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("the backup did not become ready")
}
