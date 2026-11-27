package main

import (
	json "encoding/json/v2"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/accounts"
)

// pollScan reads a scan until it ended.
func pollScan(t *testing.T, c *http.Client, base, id string) map[string]any {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		resp, body := get(t, c, base+"/api/discovery/scans/"+id)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("scan view: %d %s", resp.StatusCode, body)
		}
		var view map[string]any
		if err := json.Unmarshal([]byte(body), &view); err != nil {
			t.Fatal(err)
		}
		if view["state"] != "running" {
			return view
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("scan did not end")
	return nil
}

// The routes of the area are wired behind the session, CSRF and origin
// checks, the permission of a new installation (administrators only) and
// the page flag.
func TestDiscoveryOverHTTP(t *testing.T) {
	sys, ts := openTestSystem(t, nil)
	admin := signUp(t, ts.URL, "admin1", "first-password-1")
	if _, err := sys.accounts.Create(t.Context(), accounts.CreateRequest{Username: "user2", Password: "second-password-2", ByAdmin: true}); err != nil {
		t.Fatal(err)
	}
	user := signIn(t, ts.URL, "user2", "second-password-2")

	if _, page := get(t, admin, ts.URL+"/"); !strings.Contains(page, `id="hostDiscoveryDialog"`) {
		t.Error("the workspace offers no discovery to the administrator")
	}
	if _, page := get(t, user, ts.URL+"/"); strings.Contains(page, `id="hostDiscoveryDialog"`) {
		t.Error("the workspace offers discovery to an account without the permission")
	}
	if status, body := apiCall(t, user, ts.URL, http.MethodPost, "/api/discovery/scans", map[string]any{"network": "127.0.0.1"}, ""); status != http.StatusForbidden {
		t.Fatalf("scan without permission: %d %s", status, body)
	}
	if status, body := apiCall(t, user, ts.URL, http.MethodPost, "/api/overview/reachability", nil, ""); status != http.StatusForbidden {
		t.Fatalf("reachability without permission: %d %s", status, body)
	}

	// Port 1 of the loopback address answers nothing: the scan ends with
	// one address checked and nothing found.
	status, body := apiCall(t, admin, ts.URL, http.MethodPost, "/api/discovery/scans", map[string]any{"network": "127.0.0.1", "ports": []int{1}}, "")
	if status != http.StatusAccepted {
		t.Fatalf("scan: %d %s", status, body)
	}
	var started map[string]any
	if err := json.Unmarshal([]byte(body), &started); err != nil {
		t.Fatal(err)
	}
	view := pollScan(t, admin, ts.URL, started["id"].(string))
	if view["state"] != "done" || view["checked"] != 1.0 || len(view["found"].([]any)) != 0 {
		t.Fatalf("finished scan: %v", view)
	}
	if resp, _ := get(t, user, ts.URL+"/api/discovery/scans/"+started["id"].(string)); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("another account reads the scan: %d", resp.StatusCode)
	}
	if status, body := apiCall(t, admin, ts.URL, http.MethodPost, "/api/overview/reachability", nil, ""); status != http.StatusOK ||
		!strings.Contains(body, `"results":{}`) {
		t.Fatalf("reachability: %d %s", status, body)
	}
	if resp, body := get(t, admin, ts.URL+"/api/overview/status"); resp.StatusCode != http.StatusOK || !strings.Contains(body, `"reachability":true`) {
		t.Fatalf("status: %d %s", resp.StatusCode, body)
	}
}

// The administrator switches host_discovery_users and
// host_reachability_users (OP3) are what the discovery and reachability
// routes (HO2) check: turning them on lets a plain account in, turning
// them off shuts it out again.
func TestDiscoveryPermissionFollowsTheAdminSwitches(t *testing.T) {
	sys, ts := openTestSystem(t, nil)
	signUp(t, ts.URL, "admin1", "first-password-1")
	if _, err := sys.accounts.Create(t.Context(), accounts.CreateRequest{Username: "user2", Password: "second-password-2", ByAdmin: true}); err != nil {
		t.Fatal(err)
	}
	user := signIn(t, ts.URL, "user2", "second-password-2")
	reach := func() int {
		status, _ := apiCall(t, user, ts.URL, http.MethodPost, "/api/overview/reachability", nil, "")
		return status
	}
	scan := func() int {
		status, _ := apiCall(t, user, ts.URL, http.MethodPost, "/api/discovery/scans", map[string]any{"network": "127.0.0.1", "ports": []int{1}}, "")
		return status
	}
	if reach() != http.StatusForbidden || scan() != http.StatusForbidden {
		t.Fatal("a plain account may use discovery before the switches are on")
	}
	for _, on := range []bool{true, false} {
		if _, err := sys.settings.UpdateAdmin(t.Context(), map[string]any{"host_discovery_users": on, "host_reachability_users": on}); err != nil {
			t.Fatal(err)
		}
		if got := reach() != http.StatusForbidden; got != on {
			t.Errorf("reachability with the switch %v: allowed %v", on, got)
		}
		if got := scan() != http.StatusForbidden; got != on {
			t.Errorf("discovery with the switch %v: allowed %v", on, got)
		}
	}
}
