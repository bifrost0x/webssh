package e2eseed

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"log/slog"
	"slices"
	"strings"
	"testing"
)

func loadSeed(t *testing.T) *Seed {
	t.Helper()
	s, err := Load(checkedInSeed)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestApplyCheckedInSeed(t *testing.T) {
	t.Parallel()
	s, f := loadSeed(t), newFakeStores()
	var logs bytes.Buffer
	a, err := Apply(t.Context(), s, f.stores(), slog.New(slog.NewTextHandler(&logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	admin, user, mixed := a.Users["admin"], a.Users["user"], a.Users["mixed_mfa"]
	if len(a.Users) != 4 || !f.admins[admin] || f.admins[user] {
		t.Fatalf("users = %v, admins = %v", a.Users, f.admins)
	}
	if !f.mfa[mixed] || len(f.mfa) != 1 {
		t.Fatalf("mfa = %v", f.mfa)
	}
	wantSkipped := []string{"admin_settings.automation_enabled", "external_identities", "commands", "command_sets",
		"test_hooks.automation_ssh_peer", "test_hooks.socket_herdr_sessions"}
	if !slices.Equal(a.Skipped, wantSkipped) {
		t.Fatalf("skipped = %q", a.Skipped)
	}
	for _, part := range wantSkipped {
		if !strings.Contains(logs.String(), part) {
			t.Errorf("skipped part %s not logged", part)
		}
	}
	// Order of run_app.py: settings before accounts, accounts before
	// everything that refers to them, keys before routes before profiles.
	order := []string{"registration true", "limits 100 1000", "account e2e_admin", "onboarding 1 completed true",
		"mfa 4", "feature totp true 1", "totp 4 E2E authenticator true", "passkey 4 E2E passkey e2e-mixed-passkey 0",
		"key 1 E2E usable key", "jump 1 E2E key jump host", "socks 1 E2E none SOCKS proxy", "profiles 1 23", "profiles 2 1"}
	last := -1
	for _, call := range order {
		i := slices.Index(f.calls, call)
		if i <= last {
			t.Fatalf("call %q at %d, want after %d; calls = %q", call, i, last, f.calls)
		}
		last = i
	}
	if n := countPrefix(f.calls, "onboarding "); n != 4 {
		t.Errorf("onboarding for %d accounts, want 4", n)
	}

	var keyID string
	for id, k := range f.keys {
		keyID = id
		if len(k) != ed25519.PrivateKeySize {
			t.Fatalf("generated key has %d bytes", len(k))
		}
	}
	profiles := map[string]ProfileRecord{}
	for _, p := range f.profiles[admin] {
		profiles[p.ID] = p
	}
	if got := f.profiles[admin][0].ID; got != "password-review" {
		t.Errorf("first profile = %s, display order lost", got)
	}
	checks := []struct {
		id, got, want string
	}{
		{"usable-key", profiles["usable-key"].KeyID, keyID},
		{"missing-key", profiles["missing-key"].KeyID, "missing-key"},
		{"key-jump-host", profiles["key-jump-host"].JumpHostID, firstKey(f.jumps)},
		{"missing-jump-host", profiles["missing-jump-host"].JumpHostID, "missing-jump-host"},
		{"missing-socks-host", profiles["missing-socks-host"].SOCKSProxyID, "missing-socks-proxy"},
		{"post-none", profiles["post-none"].StartupMode, "none"},
		{"post-command-set", profiles["post-command-set"].CommandSetID, "e2e-command-set"},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s: got %q, want %q", c.id, c.got, c.want)
		}
	}
	if j := f.jumps[firstKey(f.jumps)]; j.KeyID != keyID {
		t.Errorf("jump host key = %q, want %q", j.KeyID, keyID)
	}
	if p := profiles["post-command-empty"].ParametersOverride; p == nil || *p != "" {
		t.Error("empty parameters_override lost")
	}
	if profiles["post-command-default"].ParametersOverride != nil {
		t.Error("missing parameters_override became a value")
	}
	if p := profiles["socks-password-host"]; p.SOCKSProxyID == "" || p.SOCKSProxyID == profiles["socks-key-host"].SOCKSProxyID {
		t.Error("SOCKS references not resolved per proxy")
	}
}

func countPrefix(calls []string, prefix string) int {
	n := 0
	for _, c := range calls {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}

func firstKey[V any](m map[string]V) string {
	for k := range m {
		return k
	}
	return ""
}

func TestApplyGeneratesFreshKeys(t *testing.T) {
	t.Parallel()
	var keys []ed25519.PrivateKey
	for range 2 {
		f := newFakeStores()
		if _, err := Apply(t.Context(), loadSeed(t), f.stores(), slog.New(slog.DiscardHandler)); err != nil {
			t.Fatal(err)
		}
		keys = append(keys, f.keys[firstKey(f.keys)])
	}
	if keys[0].Equal(keys[1]) {
		t.Fatal("two runs share a key")
	}
}

func TestApplyStopsAtFirstStoreError(t *testing.T) {
	t.Parallel()
	for _, failOn := range []string{"registration true", "account e2e_user", "mfa 4", "feature passkey true 1",
		"totp 4 E2E authenticator true", "key 1 E2E usable key", "jump 1 E2E key jump host",
		"socks 1 E2E password SOCKS proxy", "profiles 1 23", "onboarding 2 completed true", "limits 100 1000"} {
		f := newFakeStores()
		f.failOn = failOn
		_, err := Apply(t.Context(), loadSeed(t), f.stores(), slog.New(slog.DiscardHandler))
		if err == nil || !strings.Contains(err.Error(), "fake store refused") {
			t.Errorf("%s: err = %v", failOn, err)
		}
		if f.calls[len(f.calls)-1] != failOn {
			t.Errorf("%s: applier went on after the error: %q", failOn, f.calls[len(f.calls)-1])
		}
	}
}

func TestApplyRequiresEveryStore(t *testing.T) {
	t.Parallel()
	f := newFakeStores()
	st := f.stores()
	st.Factors = nil
	if _, err := Apply(t.Context(), loadSeed(t), st, slog.New(slog.DiscardHandler)); err == nil {
		t.Fatal("applied without the factor store")
	}
	if len(f.calls) != 0 {
		t.Fatalf("stores touched before the check: %q", f.calls)
	}
}

func TestApplyValidatesAgain(t *testing.T) {
	t.Parallel()
	s := loadSeed(t)
	s.Profiles[0].Key = "nope"
	f := newFakeStores()
	if _, err := Apply(context.Background(), s, f.stores(), slog.New(slog.DiscardHandler)); err == nil || len(f.calls) != 0 {
		t.Fatalf("err = %v, calls = %q", err, f.calls)
	}
}

func TestApplyLoginLimits(t *testing.T) {
	t.Parallel()
	one, ten := 1, 10
	for name, as := range map[string]AdminSettings{
		"only per user":  {LoginUsernameLimit: &ten},
		"global too low": {LoginUsernameLimit: &ten, LoginUsernameGlobalLimit: &one},
	} {
		if err := applyAdminSettings(t.Context(), as, newFakeStores()); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
