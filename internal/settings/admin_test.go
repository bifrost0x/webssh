package settings

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	json "encoding/json/v2"

	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/principal/principaltest"
	"github.com/bifrost0x/webssh/internal/store"
)

type auditRec struct {
	mu     sync.Mutex
	events []string
}

func (a *auditRec) add(level, e string, kv []any) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, level+" "+e+" "+fmt.Sprint(kv...))
}
func (a *auditRec) Security(e string, kv ...any)        { a.add("INFO", e, kv) }
func (a *auditRec) SecurityWarning(e string, kv ...any) { a.add("WARNING", e, kv) }

type adminFixture struct {
	h      *AdminHTTP
	mux    *http.ServeMux
	steps  *principaltest.StepUp
	audit  *auditRec
	db     *store.DB
	admin  principal.Principal
	change []map[string]AdminChange
}

func newAdmin(t *testing.T, env Environment) *adminFixture {
	t.Helper()
	s, db := newService(t, env)
	f := &adminFixture{steps: &principaltest.StepUp{}, audit: &auditRec{}, db: db, admin: principaltest.Admin(1)}
	f.h = &AdminHTTP{Settings: s, StepUp: f.steps, Audit: f.audit, Enabled: true, TailscaleSSHEnabled: true,
		Changed: func(_ context.Context, c map[string]AdminChange) { f.change = append(f.change, c) }}
	f.mux = http.NewServeMux()
	f.h.Register(f.mux)
	return f
}

func (f *adminFixture) do(t *testing.T, p principal.Principal, method, body string, grant bool) (int, map[string]any) {
	t.Helper()
	r := httptest.NewRequest(method, "/admin/api/settings", strings.NewReader(body))
	if grant {
		f.steps.Issue(p, principal.ActionSettingsUpdate, "global", "g")
		r.Header.Set(StepUpHeader, "g")
	}
	r = r.WithContext(principal.With(r.Context(), p))
	w := httptest.NewRecorder()
	f.mux.ServeHTTP(w, r)
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("%s: %v: %s", body, err, w.Body.String())
	}
	return w.Code, out
}

func (f *adminFixture) post(t *testing.T, body string) (int, map[string]any) {
	t.Helper()
	return f.do(t, f.admin, http.MethodPost, body, true)
}

func TestAdminSettingsView(t *testing.T) {
	t.Parallel()
	f := newAdmin(t, Environment{Values: map[string]bool{"TMUX_ENABLED": true, "AUTOMATION_ENABLED": true},
		Explicit: map[string]bool{"TMUX_ENABLED": true}})
	code, body := f.do(t, f.admin, http.MethodGet, "", false)
	if code != 200 {
		t.Fatal(code, body)
	}
	want := map[string]any{
		"registration_enabled": false, "ssh_gateway_enabled": false, "herdr_enabled": false, "support_links_enabled": true,
		"credentials_enabled": false, "automation_enabled": false, "tailscale_ssh_restrict_tailnet_routes": true,
		"tailscale_ssh_enabled": true, "tmux_enabled": true, "tmux_default": false, "sftp_chmod_enabled": false,
		"server_operations_enabled": false, "login_username_limit": 10.0, "login_username_global_limit": 100.0,
		"ratelimit_ipv6_prefix": 128.0, SettingDiscoveryUsers: false, SettingReachabilityUsers: false,
	}
	for k, v := range want {
		if body[k] != v {
			t.Errorf("%s = %v, want %v", k, body[k], v)
		}
	}
	tmux := body["runtime_features"].(map[string]any)["tmux_enabled"].(map[string]any)
	if tmux["source"] != "compose" || tmux["locked"] != true || tmux["environment_key"] != "TMUX_ENABLED" || tmux["saved_value"] != nil {
		t.Errorf("tmux policy %v", tmux)
	}
	src := body["setting_sources"].(map[string]any)["automation_enabled"].(map[string]any)
	if src["locked"] != false || src["source"] != "admin" {
		t.Errorf("automation source %v", src)
	}
}

func TestAdminSettingsAccess(t *testing.T) {
	t.Parallel()
	f := newAdmin(t, Environment{})
	if code, _ := f.do(t, principaltest.User(2), http.MethodGet, "", false); code != 403 {
		t.Errorf("non-admin GET %d", code)
	}
	if code, _ := f.do(t, principaltest.User(2), http.MethodPost, `{"herdr_enabled":true}`, true); code != 403 {
		t.Errorf("non-admin POST %d", code)
	}
	// Without a grant nothing is written.
	if code, body := f.do(t, f.admin, http.MethodPost, `{"herdr_enabled":true}`, false); code != 403 || body["code"] != "step_up_required" {
		t.Errorf("missing step-up %d %v", code, body)
	}
	if app, _ := f.h.Settings.App(t.Context()); app.HerdrEnabled {
		t.Error("herdr enabled without step-up")
	}
	f.h.Enabled = false
	r := httptest.NewRequest(http.MethodGet, "/admin/api/settings", nil)
	r = r.WithContext(principal.With(r.Context(), f.admin))
	w := httptest.NewRecorder()
	f.mux.ServeHTTP(w, r)
	if w.Code != 404 {
		t.Errorf("disabled panel %d", w.Code)
	}
}

func TestAdminSettingsRefusals(t *testing.T) {
	t.Parallel()
	f := newAdmin(t, Environment{Production: true, Values: map[string]bool{"TMUX_ENABLED": false, "AUTOMATION_ENABLED": true},
		Explicit: map[string]bool{"TMUX_ENABLED": true, "AUTOMATION_ENABLED": true}})
	cases := []struct {
		body   string
		status int
		want   string
	}{
		{`[]`, 400, `"error":"Invalid settings payload"`},
		{`not json`, 400, `"error":"Invalid settings payload"`},
		{`{"automation_enabled":false}`, 409, `"code":"deployment_locked"`},
		{`{"tmux_enabled":1}`, 400, `"error":"Expected a boolean"`},
		{`{"tmux_enabled":true}`, 409, `"setting":"tmux_enabled"`},
		{`{"herdr_enabled":"yes"}`, 400, `"error":"herdr_enabled must be a boolean"`},
		{`{"host_discovery_users":1}`, 400, `"error":"host_discovery_users must be a boolean"`},
		{`{"login_username_limit":0}`, 400, `"code":"out_of_range"`},
		{`{"login_username_limit":true}`, 400, `"code":"out_of_range"`},
		{`{"login_username_limit":5.0}`, 400, `"code":"out_of_range"`},
		{`{"ratelimit_ipv6_prefix":47}`, 400, `"min":48`},
		{`{"registration_enabled":null}`, 400, `"error":"registration_enabled must be a boolean"`},
		{`{"registration_enabled":true}`, 400, `production profile`},
		{`{"login_username_limit":500,"login_username_global_limit":100}`, 400, `"code":"global_limit_below_source_limit"`},
	}
	for _, c := range cases {
		code, body := f.post(t, c.body)
		raw, _ := json.Marshal(body)
		if code != c.status || !strings.Contains(string(raw), c.want) {
			t.Errorf("%s: %d %s", c.body, code, raw)
		}
	}
	if len(f.change) != 0 {
		t.Errorf("refused requests changed %v", f.change)
	}
	// Production allows closing registration.
	if code, body := f.post(t, `{"registration_enabled":false,"unknown_member":1}`); code != 200 || body["registration_enabled"] != false {
		t.Errorf("close registration %d %v", code, body)
	}
}

func TestAdminSettingsUpdate(t *testing.T) {
	t.Parallel()
	f := newAdmin(t, Environment{Values: map[string]bool{"REGISTRATION_ENABLED": false}})
	code, body := f.post(t, `{"herdr_enabled":true,"ssh_gateway_enabled":true,"credentials_enabled":true,`+
		`"automation_enabled":true,"tmux_default":true,"login_username_limit":20,"host_discovery_users":true,`+
		`"host_reachability_users":true,"tailscale_ssh_restrict_tailnet_routes":false}`)
	if code != 200 {
		t.Fatal(code, body)
	}
	app, err := f.h.Settings.App(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !app.HerdrEnabled || !app.SSHGatewayEnabled || !app.CredentialsEnabled || !app.AutomationEnabled ||
		app.TailnetRouteRestricted || app.SignIn.UsernameLimit != 20 || !app.RuntimeFeature("tmux_default").Enabled ||
		app.RuntimeFeature("tmux_default").Source != "admin" {
		t.Errorf("app after update %+v", app)
	}
	if !Granted(app.Policy.Discovery, RoleUser, false) || !Granted(app.Policy.Reachability, RoleUser, false) {
		t.Errorf("role permissions %+v", app.Policy)
	}
	rev := app.CredentialsRevision
	if len(rev) != 64 {
		t.Errorf("credentials revision %q", rev)
	}
	// The same value again keeps the revision; a change rotates it.
	f.post(t, `{"credentials_enabled":true}`)
	if app, _ := f.h.Settings.App(t.Context()); app.CredentialsRevision != rev {
		t.Error("unchanged switch rotated the revision")
	}
	f.post(t, `{"credentials_enabled":false}`)
	if app, _ := f.h.Settings.App(t.Context()); app.CredentialsRevision == rev || app.CredentialsEnabled {
		t.Error("changed switch kept the revision")
	}
	joined := strings.Join(f.audit.events, "\n")
	for _, want := range []string{
		"WARNING APPLICATION_FEATURE_CHANGED adminuser1featuressh_gateway_enabledenabledtrue",
		"INFO APPLICATION_FEATURE_CHANGED adminuser1featureherdr_enabledenabledtrue",
		"WARNING APPLICATION_FEATURE_CHANGED adminuser1featuretailscale_ssh_restrict_tailnet_routesenabledfalse",
		"WARNING APPLICATION_FEATURE_CHANGED adminuser1featurelogin_username_limitprevious_value10value20",
		"WARNING APPLICATION_FEATURE_CHANGED adminuser1featurehost_discovery_usersenabledtrue",
		"INFO RUNTIME_FEATURE_CHANGED adminuser1featuretmux_defaultenabledtrue",
		"INFO APPLICATION_FEATURE_CHANGED adminuser1featurecredentials_enabledenabledfalse",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("audit misses %q in\n%s", want, joined)
		}
	}
	if c := f.change[0]["ssh_gateway_enabled"]; c.Previous != nil || c.Current != true {
		t.Errorf("gateway change %+v", c)
	}
	// Turning the permission off again keeps other roles as stored.
	f.post(t, `{"host_discovery_users":false}`)
	if app, _ := f.h.Settings.App(t.Context()); Granted(app.Policy.Discovery, RoleUser, false) || !Granted(app.Policy.Discovery, RoleUser, true) {
		t.Errorf("discovery after revoke %+v", app.Policy)
	}
}

func TestAdminRuntimeFeatureLeavesMigration(t *testing.T) {
	t.Parallel()
	f := newAdmin(t, Environment{})
	importApp(t, f.db, `{"schema_version":2,"tmux_enabled":true,"runtime_feature_migration":["tmux_enabled","tmux_default"],"tmux_default":false}`)
	if app, _ := f.h.Settings.App(t.Context()); !app.RuntimeFeature("tmux_enabled").Migrated {
		t.Fatal("fixture not migrated")
	}
	f.post(t, `{"tmux_enabled":false}`)
	app, _ := f.h.Settings.App(t.Context())
	if st := app.RuntimeFeature("tmux_enabled"); st.Migrated || st.Enabled || st.Source != "admin" {
		t.Errorf("tmux after admin choice %+v", st)
	}
	if !app.RuntimeFeature("tmux_default").Migrated {
		t.Error("other migrated feature lost its mark")
	}
}

func TestAuditBackupCount(t *testing.T) {
	t.Parallel()
	s, _ := newService(t, Environment{AuditBackupCount: 5})
	for _, n := range []int{0, 91} {
		if err := s.SetAuditBackupCount(t.Context(), n); err == nil {
			t.Errorf("%d accepted", n)
		}
	}
	if err := s.SetAuditBackupCount(t.Context(), 30); err != nil {
		t.Fatal(err)
	}
	if app, _ := s.App(t.Context()); app.AuditBackupCount != 30 {
		t.Errorf("count %d", app.AuditBackupCount)
	}
}
