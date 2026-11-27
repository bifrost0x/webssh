package main

import (
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/backup"
	"github.com/bifrost0x/webssh/internal/config"
	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
)

func lookupMap(m map[string]string) config.LookupFunc {
	return func(name string) (string, bool) { v, ok := m[name]; return v, ok }
}

// openTestSystem wires the whole system on a fresh data directory.
func openTestSystem(t *testing.T, extra map[string]string) (*system, *httptest.Server) {
	t.Helper()
	env := map[string]string{
		"DATA_DIR": filepath.Join(t.TempDir(), "data"), "SECRET_KEY": "system-test-secret-0123456789abcdef",
		"SESSION_COOKIE_SECURE": "false", "BOOTSTRAP_REGISTRATION_ENABLED": "true", "TMPDIR": t.TempDir(),
	}
	maps.Copy(env, extra)
	sys, err := openSystem(t.Context(), bootInput{lookup: lookupMap(env), log: slog.New(slog.DiscardHandler),
		stopping: func() bool { return false }, fastHashing: true})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(sys.handler())
	t.Cleanup(func() {
		ts.Close()
		if err := sys.close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	return sys, ts
}

func get(t *testing.T, c *http.Client, u string) (*http.Response, string) {
	t.Helper()
	resp, err := c.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(b)
}

func TestSystemServesThePreview(t *testing.T) {
	_, ts := openTestSystem(t, nil)
	anon := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if resp, _ := get(t, anon, ts.URL+"/"); resp.StatusCode != http.StatusFound || !strings.HasPrefix(resp.Header.Get("Location"), "/login") {
		t.Fatalf("anonymous workspace: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	if resp, body := get(t, anon, ts.URL+"/ready"); resp.StatusCode != http.StatusOK || !strings.Contains(body, `"ready"`) {
		t.Fatalf("ready: %d %s", resp.StatusCode, body)
	}

	c := signUp(t, ts.URL, "admin1", "first-password-1")
	resp, body := get(t, c, ts.URL+"/")
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `id="initialInventory"`) || !strings.Contains(body, `id="websshPreview"`) {
		t.Fatalf("workspace: %d", resp.StatusCode)
	}
	for _, want := range []string{`"automation"`} {
		if !strings.Contains(body, want) {
			t.Errorf("preview notice lacks %s", want)
		}
	}
	// Server operations and Herdr are built (HO1).
	for _, gone := range []string{`"serverOps"`} {
		if strings.Contains(body, gone) {
			t.Errorf("preview notice still names %s", gone)
		}
	}
	if resp, body := get(t, c, ts.URL+"/security"); resp.StatusCode != http.StatusOK || !strings.Contains(body, "WebSSH password") {
		t.Fatalf("security: %d", resp.StatusCode)
	}
	noFollow := *c
	noFollow.CheckRedirect = anon.CheckRedirect
	if resp, _ := get(t, &noFollow, ts.URL+"/admin"); resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/security?section=users" {
		t.Fatalf("admin: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	if resp, body := get(t, c, ts.URL+"/api/account/recovery-check"); resp.StatusCode != http.StatusOK || !strings.Contains(body, `"needs_review":false`) {
		t.Fatalf("recovery-check: %d %s", resp.StatusCode, body)
	}
	// WEBAUTHN_ENABLED is off by default, as in Python.
	if resp, body := get(t, c, ts.URL+"/api/webauthn/credentials"); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("passkeys while disabled: %d %s", resp.StatusCode, body)
	}
	if resp, body := get(t, c, ts.URL+"/api/realtime/status"); resp.StatusCode != http.StatusOK || !strings.Contains(body, `"authenticated":true`) {
		t.Fatalf("realtime status: %d %s", resp.StatusCode, body)
	}
	if resp, _ := get(t, c, ts.URL+"/api/overview/status"); resp.StatusCode != http.StatusOK {
		t.Fatalf("overview status: %d", resp.StatusCode)
	}
}

func TestMaintenanceAnswersOnlyTheProbes(t *testing.T) {
	sys, ts := openTestSystem(t, nil)
	leave, err := sys.maintenance.Enter(t.Context(), backup.MaintenanceRestore)
	if err != nil {
		t.Fatal(err)
	}
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar, Timeout: 5 * time.Second}
	if resp, body := get(t, c, ts.URL+"/login"); resp.StatusCode != http.StatusServiceUnavailable || !strings.Contains(body, `"maintenance"`) {
		t.Fatalf("login in maintenance: %d %s", resp.StatusCode, body)
	}
	if resp, _ := get(t, c, ts.URL+"/health"); resp.StatusCode != http.StatusOK {
		t.Fatalf("health in maintenance: %d", resp.StatusCode)
	}
	if resp, body := get(t, c, ts.URL+"/ready"); resp.StatusCode != http.StatusServiceUnavailable || !strings.Contains(body, "maintenance") {
		t.Fatalf("ready in maintenance: %d %s", resp.StatusCode, body)
	}
	leave()
	if resp, body := get(t, c, ts.URL+"/ready"); resp.StatusCode != http.StatusOK {
		t.Fatalf("ready after maintenance: %d %s", resp.StatusCode, body)
	}
	if resp, _ := get(t, c, ts.URL+"/login"); resp.StatusCode != http.StatusOK {
		t.Fatalf("login after maintenance: %d", resp.StatusCode)
	}
}

func TestSystemRefusesUnsafeProduction(t *testing.T) {
	_, err := openSystem(t.Context(), bootInput{lookup: lookupMap(map[string]string{
		"DATA_DIR": filepath.Join(t.TempDir(), "data"), "SECRET_KEY": "x-0123456789abcdef0123456789", "DEPLOYMENT_PROFILE": "production",
	}), log: slog.New(slog.DiscardHandler), stopping: func() bool { return false }})
	if err == nil || !strings.Contains(err.Error(), "unsafe production profile") {
		t.Fatalf("unsafe production profile: %v", err)
	}
}

// The production profile starts and keeps its rules at run time:
// registration stays locked and cannot be enabled by an administrator.
func TestSystemProductionProfile(t *testing.T) {
	sys, ts := openTestSystem(t, map[string]string{
		"DEPLOYMENT_PROFILE": "production", "CORS_ORIGINS": "https://ssh.example.com", "BLOCK_INTERNAL_SSH": "true",
		"TRUSTED_PROXIES": "0", "SESSION_COOKIE_SECURE": "true", "BOOTSTRAP_REGISTRATION_ENABLED": "false",
	})
	if sys.cfg.Profile != config.ProfileProduction || sys.cfg.Features.HostDiscovery || sys.cfg.Accounts.BootstrapRegistrationEnabled {
		t.Fatalf("production configuration %+v %+v", sys.cfg.Features, sys.cfg.Accounts)
	}
	app, err := sys.settings.App(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if app.RegistrationEnabled {
		t.Error("registration open in production")
	}
	if err := sys.settings.SetRegistrationEnabled(t.Context(), true); err == nil {
		t.Error("registration enabled in production")
	}
	if resp, _ := get(t, ts.Client(), ts.URL+"/health"); resp.StatusCode != http.StatusOK {
		t.Errorf("health: %d", resp.StatusCode)
	}
}

func TestHostAdapters(t *testing.T) {
	sys, _ := openTestSystem(t, nil)
	ctx := t.Context()
	trust := hostTrust{sys.hostkeys}
	for _, host := range []string{"bad host!", "", "*.example"} {
		if ok, err := trust.Trusted(ctx, 1, host, 22); ok || err != nil {
			t.Errorf("Trusted(%q) = %v, %v", host, ok, err)
		}
	}
	if ok, err := trust.Trusted(ctx, 1, "Unknown.Example.", 22); ok || err != nil {
		t.Errorf("unknown host trusted: %v %v", ok, err)
	}
	inv := overviewInventory{hosts: sys.hosts, vault: sys.vault}
	if _, err := inv.OverviewInventory(ctx, 1); fault.CodeOf(err) != fault.Forbidden {
		t.Errorf("without principal: %v", err)
	}
	other := principal.With(ctx, principal.Principal{UserID: 2, SessionID: "s"})
	if _, err := inv.OverviewInventory(other, 1); fault.CodeOf(err) != fault.Forbidden {
		t.Errorf("another account's inventory: %v", err)
	}
	own := principal.With(ctx, principal.Principal{UserID: 1, SessionID: "s"})
	got, err := inv.OverviewInventory(own, 1)
	if err != nil || len(got.Hosts) != 0 || got.SOCKSProxies == nil {
		t.Errorf("empty inventory: %+v %v", got, err)
	}
	targets, err := sshTargets{sys.hosts}.SSHTargets(ctx, 1)
	if err != nil || len(targets) != 0 {
		t.Errorf("targets %v %v", targets, err)
	}
}

func TestRecoveryFactorFollowsTheCodes(t *testing.T) {
	sys, _ := openTestSystem(t, nil)
	f := recoveryFactor{sys.db}
	if f.Kind() != "recovery" {
		t.Fatal(f.Kind())
	}
	if ok, err := f.Enrolled(t.Context(), 1); ok || err != nil {
		t.Fatalf("without codes: %v %v", ok, err)
	}
	if _, err := sys.recovery.Generate(t.Context(), 1); err != nil {
		t.Fatal(err)
	}
	if ok, err := f.Enrolled(t.Context(), 1); !ok || err != nil {
		t.Fatalf("with codes: %v %v", ok, err)
	}
	if err := f.Verify(t.Context(), 1, nil); fault.CodeOf(err) != fault.AuthFailed {
		t.Fatalf("Verify: %v", err)
	}
}

// With WEBAUTHN_ENABLED the passkey extension is ready, is a factor of
// MFA, step-up and sign-in, and serves its routes.
func TestSystemWiresPasskeys(t *testing.T) {
	sys, ts := openTestSystem(t, map[string]string{"WEBAUTHN_ENABLED": "true"})
	if !sys.optional.featureReady["passkey"].Ready || sys.mfa.Passkeys == nil || sys.stepup.Passkeys == nil {
		t.Fatal("passkeys not wired")
	}
	kinds := []string{}
	for _, f := range sys.flow.Factors {
		kinds = append(kinds, f.Kind())
	}
	if !slices.Contains(kinds, "passkey") {
		t.Fatalf("sign-in factors %v", kinds)
	}
	if _, ok := sys.stepup.Targets[principal.ActionPasskeyDelete]; !ok {
		t.Fatal("no step-up target check for passkey deletion")
	}
	c := signUp(t, ts.URL, "admin1", "first-password-1")
	if resp, body := get(t, c, ts.URL+"/api/webauthn/credentials"); resp.StatusCode != http.StatusOK || body != `{"credentials":[]}` {
		t.Fatalf("passkey list: %d %s", resp.StatusCode, body)
	}
	if resp, body := get(t, c, ts.URL+"/security"); resp.StatusCode != http.StatusOK || !strings.Contains(body, `id="passkeyAddBtn"`) {
		t.Fatalf("security page without passkeys: %d", resp.StatusCode)
	}
}
