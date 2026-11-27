package main

import (
	"net/http"
	"strings"
	"testing"

	json "encoding/json/v2"

	"github.com/bifrost0x/webssh/internal/accounts"
)

// The support report never carries secrets, account names or local
// paths, whatever the configuration holds: the server is started with
// fixture secrets and the reports of a user and an administrator are
// searched for them.
func TestSupportReportCarriesNoSecrets(t *testing.T) {
	const secretKey = "fixture-secret-key-SUPPORT-0123456789abcdef"
	sys, ts := openTestSystem(t, map[string]string{"SECRET_KEY": secretKey, "ADMIN_PANEL_ENABLED": "true"})
	admin := signUp(t, ts.URL, "supportadmin", "fixture-admin-password-1")
	if _, err := sys.accounts.Create(t.Context(), accounts.CreateRequest{Username: "supportbob", Password: "fixture-bob-password-1", ByAdmin: true}); err != nil {
		t.Fatal(err)
	}
	bob := signIn(t, ts.URL, "supportbob", "fixture-bob-password-1")
	secrets := []string{secretKey, "fixture-admin-password-1", "fixture-bob-password-1", "supportbob", "supportadmin", sys.cfg.DataDir}

	status, body := apiCall(t, bob, ts.URL, http.MethodPost, "/api/account/support-report", map[string]string{"area": "files", "reference": "SMB-ABCDEF123456"}, "")
	if status != http.StatusOK {
		t.Fatalf("user report: %d %s", status, body)
	}
	var report map[string]any
	if err := json.Unmarshal([]byte(body), &report); err != nil {
		t.Fatal(err)
	}
	if _, ok := report["deployment"]; ok || report["reference"] != "SMB-ABCDEF123456" || report["schema"] != 1.0 {
		t.Errorf("user report %s", body)
	}
	status, adminBody := apiCall(t, admin, ts.URL, http.MethodPost, "/api/account/support-report", map[string]string{}, "")
	if status != http.StatusOK || !strings.Contains(adminBody, `"deployment":{"profile":"homelab"`) {
		t.Errorf("admin report: %d %s", status, adminBody)
	}
	for _, s := range secrets {
		if strings.Contains(body, s) || strings.Contains(adminBody, s) {
			t.Errorf("report contains %q", s)
		}
	}
	if status, _ := apiCall(t, bob, ts.URL, http.MethodPost, "/api/account/support-report", map[string]string{"area": "logs"}, ""); status != http.StatusBadRequest {
		t.Errorf("unknown area: %d", status)
	}
}

// The administrator settings, the instance status and the audit view are
// served through the whole server, only to administrators, and a change
// needs the step-up.
func TestOperationsThroughTheServer(t *testing.T) {
	sys, ts := openTestSystem(t, map[string]string{"ADMIN_PANEL_ENABLED": "true"})
	admin := signUp(t, ts.URL, "admin1", "first-password-1")
	if _, err := sys.accounts.Create(t.Context(), accounts.CreateRequest{Username: "bob", Password: "bob-password-1", ByAdmin: true}); err != nil {
		t.Fatal(err)
	}
	bob := signIn(t, ts.URL, "bob", "bob-password-1")
	for _, path := range []string{"/admin/api/settings", "/admin/api/operations", "/admin/api/operations/details", "/admin/api/audit"} {
		if resp, _ := get(t, bob, ts.URL+path); resp.StatusCode != http.StatusForbidden {
			t.Errorf("bob %s: %d", path, resp.StatusCode)
		}
		if resp, body := get(t, admin, ts.URL+path); resp.StatusCode != http.StatusOK {
			t.Errorf("admin %s: %d %s", path, resp.StatusCode, body)
		}
	}
	if status, _ := apiCall(t, admin, ts.URL, http.MethodPost, "/admin/api/settings", map[string]bool{"herdr_enabled": true}, "wrong"); status != http.StatusForbidden {
		t.Errorf("settings without grant: %d", status)
	}
	grant := adminGrant(t, admin, ts.URL, "settings.update", "global", "first-password-1")
	status, body := apiCall(t, admin, ts.URL, http.MethodPost, "/admin/api/settings",
		map[string]bool{"herdr_enabled": true, "credentials_enabled": true, "host_discovery_users": true}, grant)
	if status != http.StatusOK || !strings.Contains(body, `"herdr_enabled":true`) || !strings.Contains(body, `"host_discovery_users":true`) {
		t.Fatalf("settings: %d %s", status, body)
	}
	app, err := sys.settings.App(t.Context())
	if err != nil || !app.HerdrEnabled || !app.CredentialsEnabled {
		t.Errorf("stored settings %+v %v", app, err)
	}
	resp, status2 := get(t, admin, ts.URL+"/admin/api/operations")
	if resp.StatusCode != http.StatusOK || !strings.Contains(status2, `"accepting_work":true`) {
		t.Errorf("operations: %d %s", resp.StatusCode, status2)
	}
	resp, export := get(t, admin, ts.URL+"/admin/api/audit/export")
	if resp.StatusCode != http.StatusOK || !strings.Contains(export, "APPLICATION_FEATURE_CHANGED") ||
		resp.Header.Get("X-WebSSH-Audit-Completeness") != "complete-within-retained-logs" {
		t.Errorf("audit export: %d %s", resp.StatusCode, export)
	}
}
