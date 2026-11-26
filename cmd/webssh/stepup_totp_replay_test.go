package main

import (
	json "encoding/json/v2"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/otp"
	"github.com/bifrost0x/webssh/internal/store"
)

// A TOTP code confirms one step-up only, through the whole server: the
// code of the current step gives a grant once, its replay and the code of
// an earlier, already used step are refused (CONDITIONS R1/Final).
func TestStepUpRefusesTOTPReplayThroughTheServer(t *testing.T) {
	sys, ts := openTestSystem(t, map[string]string{"ADMIN_PANEL_ENABLED": "true", "TOTP_ENABLED": "true"})
	admin := signUp(t, ts.URL, "admin1", "first-password-1")
	if err := sys.db.Write(t.Context(), func(tx *store.Tx) error {
		_, err := tx.ExecContext(t.Context(), `INSERT INTO operations_feature_gates (feature, enabled) VALUES ('totp', 1)`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if on, err := sys.gates.Active(t.Context(), "totp"); !on || err != nil {
		t.Fatalf("TOTP not active: %v", err)
	}
	// Stay clear of a step boundary so that "this step" and "the step
	// before" keep their meaning for the whole test.
	for time.Now().Unix()%30 > 22 {
		time.Sleep(500 * time.Millisecond)
	}

	status, body := apiCall(t, admin, ts.URL, http.MethodPost, "/api/account/step-up/intents", map[string]string{"action": "totp.enroll"}, "")
	var intent struct {
		Intent string `json:"intent"`
		Grant  string `json:"grant"`
	}
	if status != http.StatusOK || json.Unmarshal([]byte(body), &intent) != nil {
		t.Fatalf("intent: %d %s", status, body)
	}
	grant := intent.Grant
	if grant == "" {
		status, body = apiCall(t, admin, ts.URL, http.MethodPost, "/api/account/step-up/password",
			map[string]string{"intent": intent.Intent, "password": "first-password-1"}, "")
		var g struct {
			Grant string `json:"grant"`
		}
		if status != http.StatusOK || json.Unmarshal([]byte(body), &g) != nil || g.Grant == "" {
			t.Fatalf("enroll step-up: %d %s", status, body)
		}
		grant = g.Grant
	}
	status, body = apiCall(t, admin, ts.URL, http.MethodPost, "/api/totp/enroll", map[string]string{"label": "phone"}, grant)
	var enrollment struct {
		Token  string `json:"token"`
		Secret string `json:"secret"`
	}
	if status != http.StatusOK || json.Unmarshal([]byte(body), &enrollment) != nil {
		t.Fatalf("enroll: %d %s", status, body)
	}
	key, err := otp.DecodeSecret(enrollment.Secret)
	if err != nil {
		t.Fatal(err)
	}
	code := func(step uint64) string {
		c, err := otp.TOTP(key, step)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	now := otp.Step(time.Now(), otp.DefaultPeriod)
	status, body = apiCall(t, admin, ts.URL, http.MethodPost, "/api/totp/enroll/verify",
		map[string]any{"token": enrollment.Token, "code": code(now - 1), "confirm_enable_mfa": true}, "")
	if status != http.StatusOK {
		t.Fatalf("activate: %d %s", status, body)
	}

	stepUp := func(c string) (int, string) {
		return apiCall(t, admin, ts.URL, http.MethodPost, "/api/step-up/totp",
			map[string]string{"action": "user.manage", "target": "1:unlock", "code": c}, "")
	}
	if status, body := stepUp(code(now)); status != http.StatusOK {
		t.Fatalf("first use of the code: %d %s", status, body)
	}
	if status, body := stepUp(code(now)); status != http.StatusForbidden || !strings.Contains(body, `"code":"invalid_value"`) {
		t.Fatalf("replayed code accepted: %d %s", status, body)
	}
	if status, body := stepUp(code(now - 1)); status != http.StatusForbidden || !strings.Contains(body, `"code":"invalid_value"`) {
		t.Fatalf("code of an earlier step accepted: %d %s", status, body)
	}
}
