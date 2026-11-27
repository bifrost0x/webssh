package main

import (
	"encoding/json/jsontext"
	"net/http"
	"strings"
	"testing"

	"github.com/bifrost0x/webssh/internal/automation"
	"github.com/bifrost0x/webssh/internal/store"
)

// The schedule routes share the HTTPS rule of the automation routes: the
// documented loopback exception (DEBUG, homelab profile,
// AUTOMATION_ALLOW_INSECURE_LOOPBACK) lets a direct loopback request use
// plain HTTP, and without it both refuse with https_required.
func TestScheduleRoutesShareTheLoopbackException(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  map[string]string
		want int
	}{
		{"exception on", map[string]string{"DEBUG": "true", "AUTOMATION_ENABLED": "true", "AUTOMATION_ALLOW_INSECURE_LOOPBACK": "true"}, http.StatusOK},
		{"exception off", map[string]string{"DEBUG": "true", "AUTOMATION_ENABLED": "true"}, http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sys, ts := openTestSystem(t, tc.env)
			if sys.automationHTTP == nil {
				t.Fatal("the automation routes are not wired")
			}
			c := signUp(t, ts.URL, "admin1", "first-password-1")
			for _, path := range []string{"/api/automation/state", "/api/automation/schedules"} {
				resp, body := get(t, c, ts.URL+path)
				if resp.StatusCode != tc.want || (tc.want == http.StatusForbidden && !strings.Contains(body, "https_required")) {
					t.Errorf("%s: %d %s", path, resp.StatusCode, body)
				}
			}
		})
	}
}

// The recovery checklist lists the account's schedules (OP1-6,
// customer_workflows.py): id, name, enabled and the last status.
func TestRecoveryCheckListsSchedules(t *testing.T) {
	sys, ts := openTestSystem(t, nil)
	c := signUp(t, ts.URL, "admin1", "first-password-1")
	acc, err := sys.accounts.ByUsername(t.Context(), "admin1")
	if err != nil {
		t.Fatal(err)
	}
	if err := sys.db.Write(t.Context(), func(tx *store.Tx) error {
		return automation.ImportScheduleTx(t.Context(), tx, automation.ImportedSchedule{ID: "00000000-0000-4000-8000-000000000001",
			UserID: acc.ID, Revision: 1, Enabled: false, Cron: "15 3 * * 1", Zone: "Europe/Berlin", NextAt: 1.8e9,
			LastStatus: automation.StatusPaused, Book: jsontext.Value(`{"id":"b1","name":"Nightly","steps":[],"stop_on_error":true}`),
			Targets: []jsontext.Value{}, KeyDigests: map[string]string{}, Binding: jsontext.Value("null"),
			Account: automation.AccountBinding{Incarnation: acc.Incarnation, AuthGeneration: acc.AuthGeneration}, Policy: "r"})
	}); err != nil {
		t.Fatal(err)
	}
	resp, body := get(t, c, ts.URL+"/api/account/recovery-check")
	want := `"schedules":[{"id":"00000000-0000-4000-8000-000000000001","name":"Nightly","enabled":false,"status":"paused"}]`
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, want) {
		t.Fatalf("recovery check: %d %s", resp.StatusCode, body)
	}
}
