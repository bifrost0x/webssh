package main

import (
	"net/http"
	"strings"
	"testing"
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
