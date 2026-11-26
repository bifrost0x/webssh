package settings

import (
	"encoding/json/jsontext"
	"slices"
	"testing"

	"github.com/bifrost0x/webssh/internal/store"
)

func importApp(t *testing.T, db *store.DB, doc string) {
	t.Helper()
	write(t, db, func(tx *store.Tx) error {
		_, err := ImportApp(t.Context(), tx, jsontext.Value(doc), 1)
		return err
	})
}

func TestAppDefaults(t *testing.T) {
	s, _ := newService(t, Environment{AuditBackupCount: 7})
	a, err := s.App(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	want := App{SupportLinksEnabled: true, TailnetRouteRestricted: true, AuditBackupCount: 7,
		SignIn: SignInProtection{10, 100, 128}}
	if a.RegistrationEnabled != want.RegistrationEnabled || a.SupportLinksEnabled != want.SupportLinksEnabled ||
		a.TailnetRouteRestricted != want.TailnetRouteRestricted || a.AuditBackupCount != 7 || a.SignIn != want.SignIn ||
		a.SSHGatewayEnabled || a.HerdrEnabled || a.CredentialsEnabled || a.AutomationEnabled {
		t.Errorf("defaults %+v", a)
	}
	// New installations get the secure defaults of the derived settings.
	if p := a.Policy; p.Discovery != nil || p.Reachability != nil || p.OriginIgnoreScheme || p.LegacySSHAlgorithms {
		t.Errorf("policy %+v", p)
	}
}

func TestRegistration(t *testing.T) {
	env := Environment{Values: map[string]bool{"REGISTRATION_ENABLED": true}}
	s, db := newService(t, env)
	if a, _ := s.App(t.Context()); !a.RegistrationEnabled {
		t.Error("REGISTRATION_ENABLED is the initial value")
	}
	// A saved administrator choice wins, so an upgrade never reopens
	// registration an administrator closed.
	if err := s.SetRegistrationEnabled(t.Context(), false); err != nil {
		t.Fatal(err)
	}
	if a, _ := s.App(t.Context()); a.RegistrationEnabled {
		t.Error("saved choice ignored")
	}
	prod := New(db, Environment{Production: true, Values: map[string]bool{"REGISTRATION_ENABLED": true}})
	if err := prod.SetRegistrationEnabled(t.Context(), true); err == nil {
		t.Error("production opened registration")
	}
	if err := s.SetRegistrationEnabled(t.Context(), true); err != nil {
		t.Fatal(err)
	}
	if a, _ := prod.App(t.Context()); a.RegistrationEnabled {
		t.Error("production registers")
	}
}

func TestSignInLimits(t *testing.T) {
	s, _ := newService(t, Environment{})
	for _, c := range [][2]int{{0, 10}, {10, 9}, {1001, 1001}, {5, 1001}} {
		if err := s.SetLoginUsernameLimits(t.Context(), c[0], c[1]); err == nil {
			t.Errorf("%v accepted", c)
		}
	}
	if err := s.SetLoginUsernameLimits(t.Context(), 50, 500); err != nil {
		t.Fatal(err)
	}
	if a, _ := s.App(t.Context()); a.SignIn.UsernameLimit != 50 || a.SignIn.UsernameGlobalLimit != 500 {
		t.Errorf("%+v", a.SignIn)
	}
}

func TestEffectiveLegacyValues(t *testing.T) {
	env := Environment{
		Values:   map[string]bool{"AUTOMATION_ENABLED": false, "TMUX_ENABLED": true, "SFTP_CHMOD_ENABLED": true},
		Explicit: map[string]bool{"AUTOMATION_ENABLED": true, "TMUX_ENABLED": true},
	}
	s, db := newService(t, env)
	importApp(t, db, `{"schema_version":2,"automation_enabled":true,"support_links_enabled":false,`+
		`"tailscale_ssh_restrict_tailnet_routes":false,"ssh_gateway_enabled":true,"herdr_enabled":false,`+
		`"tmux_enabled":false,"sftp_chmod_enabled":false,"runtime_feature_migration":["tmux_enabled"],"audit_backup_count":3}`)
	a, err := s.App(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	// An explicit AUTOMATION_ENABLED locks the switch.
	if a.AutomationEnabled || a.SupportLinksEnabled || a.TailnetRouteRestricted || !a.SSHGatewayEnabled || a.HerdrEnabled || a.AuditBackupCount != 3 {
		t.Errorf("%+v", a)
	}
	tmux := a.RuntimeFeature("tmux_enabled")
	if !tmux.Enabled || tmux.Source != "compose" || !tmux.Locked || tmux.Saved == nil || *tmux.Saved || !tmux.Migrated {
		t.Errorf("tmux %+v", tmux)
	}
	chmod := a.RuntimeFeature("sftp_chmod_enabled")
	if chmod.Enabled || chmod.Source != "admin" || chmod.Migrated {
		t.Errorf("chmod %+v", chmod)
	}
	if d := a.RuntimeFeature("tmux_default"); d.Enabled || d.Source != "default" {
		t.Errorf("tmux_default %+v", d)
	}
	if u := a.RuntimeFeature("unknown"); u.Enabled {
		t.Error("unknown feature enabled")
	}
}

func TestMaterialisePolicies(t *testing.T) {
	s, db := newService(t, Environment{})
	var got []Materialised
	write(t, db, func(tx *store.Tx) error {
		var err error
		got, err = MaterialisePolicies(t.Context(), tx, Legacy{KeepLegacyScheme: true}, 1)
		return err
	})
	keys := make([]string, 0, len(got))
	for _, m := range got {
		keys = append(keys, m.Setting)
		if m.Rule == "" || m.Evidence == "" || m.Value == "" {
			t.Errorf("incomplete report entry %+v", m)
		}
	}
	if !slices.Equal(keys, []string{PolicyDiscovery, PolicyReachability, PolicyLegacySSHAlgorithms, PolicyOriginIgnoreScheme, PolicyTailnetFollowsSwitch}) {
		t.Errorf("materialised %v", keys)
	}
	a, err := s.App(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	p := a.Policy
	if !slices.Equal(p.Discovery, []string{RoleUser}) || !slices.Equal(p.Reachability, []string{RoleUser}) ||
		!p.OriginIgnoreScheme || !p.LegacySSHAlgorithms || !p.TailnetFollowsSwitch {
		t.Errorf("policy %+v", p)
	}
	if !Granted(p.Discovery, RoleUser, false) || Granted(nil, RoleUser, false) || !Granted(nil, RoleUser, true) {
		t.Error("Granted")
	}
	if len(a.MaterialisedSettings()) != 5 {
		t.Errorf("listed %v", a.MaterialisedSettings())
	}
	// Without the legacy origin rule the scheme stays compared.
	s2, db2 := newService(t, Environment{})
	write(t, db2, func(tx *store.Tx) error {
		_, err := MaterialisePolicies(t.Context(), tx, Legacy{}, 1)
		return err
	})
	if a, _ := s2.App(t.Context()); a.Policy.OriginIgnoreScheme || !a.Policy.LegacySSHAlgorithms || !a.Policy.TailnetFollowsSwitch {
		t.Errorf("policy %+v", a.Policy)
	}
	// A new installation has no row: the tailnet rule does not follow the
	// switch (D-28).
	s3, _ := newService(t, Environment{})
	if a, _ := s3.App(t.Context()); a.Policy.TailnetFollowsSwitch {
		t.Error("new installation follows the Tailscale SSH switch")
	}
}
