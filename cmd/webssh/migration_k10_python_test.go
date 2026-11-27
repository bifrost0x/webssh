package main

import (
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"log/slog"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/bifrost0x/webssh/internal/hosts"
	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/settings"
	"github.com/bifrost0x/webssh/internal/store"
)

// pythonView prints what the Python release shows each account of a
// DATA_DIR: the effective settings (get_user_settings, including the
// D-01 default of confirm_session_close for old accounts) and the saved
// hosts as loaded (load_profiles, which drops identity facts and roles
// that do not fit, #377).
const pythonView = `
import json, sys
from app import create_app
app = create_app(start_runtime=False, initialize_oidc=False)
with app.app_context():
    from app.models import User
    from app import profile_manager, user_settings
    out = {}
    for u in User.query.order_by(User.id).all():
        entry = {}
        try:
            entry['settings'] = user_settings.get_user_settings(u.id)
        except Exception as e:
            entry['settings_error'] = type(e).__name__
        try:
            entry['profiles'] = profile_manager.load_profiles(u.id)
        except Exception as e:
            entry['profiles_error'] = type(e).__name__
        out[str(u.id)] = entry
sys.stdout.write("\n--result--\n" + json.dumps(out))
`

type pythonAccount struct {
	Settings      map[string]jsontext.Value `json:"settings"`
	SettingsError string                    `json:"settings_error"`
	Profiles      []jsontext.Value          `json:"profiles"`
	ProfilesError string                    `json:"profiles_error"`
}

func pythonBinary(t *testing.T) string {
	t.Helper()
	for _, p := range []string{"../../.venv/bin/python", "/usr/bin/python"} {
		if abs, err := filepath.Abs(p); err == nil {
			if _, err := os.Stat(abs); err == nil {
				return abs
			}
		}
	}
	t.Skip("no Python virtual environment")
	return ""
}

// canonical re-encodes a JSON value with sorted member names, so that
// both sides compare by content. tailscale_authorized is response-only
// and depends on the running node; it is left out.
func canonical(t *testing.T, v jsontext.Value) string {
	t.Helper()
	var x any
	if err := json.Unmarshal(v, &x); err != nil {
		t.Fatalf("%v: %s", err, v)
	}
	if m, ok := x.(map[string]any); ok {
		delete(m, "tailscale_authorized")
	}
	out, err := json.Marshal(x, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

// Differential check of spec 8.4 over every golden DATA_DIR: after the Go
// migration each account sees the same effective settings (D-01:
// confirm_session_close of old accounts) and the same saved hosts,
// identity facts and manual roles of #377/#378 included, as the Python
// release shows on the same data.
func TestBuildMigrationShowsWhatPythonShows(t *testing.T) {
	python := pythonBinary(t)
	cases := append([]k10Fixture{{"golden with host identity", "../datadir.tar"}}, k10Fixtures...)
	for i, fx := range cases {
		t.Run(fx.name, func(t *testing.T) {
			goDir := extractGolden(t, fx.archive)
			pyDir := extractGolden(t, fx.archive)
			if i == 0 {
				addHostIdentity(t, goDir)
				addHostIdentity(t, pyDir)
			}
			cmd := exec.CommandContext(t.Context(), python, "-c", pythonView)
			cmd.Dir = "../.."
			cmd.Env = append(os.Environ(), "DATA_DIR="+pyDir, "SECRET_KEY="+goldenSecret(t), "PYTHONPATH=.", "PYTHONDONTWRITEBYTECODE=1")
			raw, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("python: %v\n%s", err, raw)
			}
			_, result, ok := strings.Cut(string(raw), "\n--result--\n")
			if !ok {
				t.Fatalf("python output: %s", raw)
			}
			var want map[string]pythonAccount
			if err := json.Unmarshal([]byte(result), &want); err != nil {
				t.Fatal(err)
			}

			_, lookup := k10Env(t, goDir)
			log := slog.New(slog.DiscardHandler)
			cfg, err := bootstrapConfig(lookup, log)
			if err != nil {
				t.Fatal(err)
			}
			st, err := startMigration(t.Context(), cfg, lookup, log)
			if err != nil {
				t.Fatal(err)
			}
			if err := st.Close(); err != nil || !st.Migrated {
				t.Fatalf("migration: %s %v", st.State, err)
			}
			db, err := store.Open(t.Context(), filepath.Join(goDir, keyring.GoDirName, keyring.DatabaseName), store.Options{})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = db.Close() }()
			sets := settings.New(db, settingsEnvironment(cfg, lookup))
			hs := &hosts.Service{DB: db}
			compared := 0
			for id, py := range want {
				uid, _ := strconv.ParseInt(id, 10, 64)
				if py.SettingsError == "" {
					u, err := sets.User(t.Context(), uid)
					if err != nil {
						t.Fatalf("user %d settings: %v", uid, err)
					}
					doc := u.Document()
					for key, pv := range py.Settings {
						if key == "notepad" || key == "workspace_presets" || key == "schema_version" {
							continue // moved to the notes (A05) and to the saved hosts (A06)
						}
						gv, ok := doc[key]
						if !ok {
							t.Errorf("user %d: setting %s missing in Go", uid, key)
							continue
						}
						if canonical(t, gv) != canonical(t, pv) {
							t.Errorf("user %d: setting %s is %s in Go, %s in Python", uid, key, gv, pv)
						}
						compared++
					}
				}
				if py.ProfilesError != "" {
					continue
				}
				got, err := hs.Profiles(t.Context(), uid)
				if err != nil {
					t.Fatalf("user %d profiles: %v", uid, err)
				}
				if len(got) != len(py.Profiles) {
					t.Errorf("user %d: %d saved hosts in Go, %d in Python", uid, len(got), len(py.Profiles))
					continue
				}
				for i := range got {
					if g, p := canonical(t, got[i]), canonical(t, py.Profiles[i]); g != p {
						t.Errorf("user %d host %d:\n go     %s\n python %s", uid, i, g, p)
					}
					compared++
				}
			}
			if compared == 0 {
				t.Fatal("nothing compared")
			}
			if i == 0 {
				got, err := hs.Profiles(t.Context(), 3)
				if err != nil {
					t.Fatal(err)
				}
				first, second := canonical(t, got[0]), canonical(t, got[1])
				if !strings.Contains(first, `"role_override":"web"`) || !strings.Contains(first, `"detected_guests":3`) {
					t.Errorf("valid identity facts lost: %s", first)
				}
				if strings.Contains(second, "role_override") || strings.Contains(second, "detected_family") {
					t.Errorf("invalid identity facts kept: %s", second)
				}
			}
			t.Logf("%d accounts, %d values compared", len(want), compared)
		})
	}
}

// addHostIdentity stores the identity facts and manual roles of #377 in
// the first saved hosts of user_3: a complete valid set, a set Python
// drops field by field on load, and the automatic role.
func addHostIdentity(t *testing.T, dataDir string) {
	t.Helper()
	path := filepath.Join(dataDir, "users", "user_3", "profiles.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	profiles, _ := doc["profiles"].([]any)
	if len(profiles) < 3 {
		t.Fatalf("%d profiles", len(profiles))
	}
	facts := []map[string]any{{
		"detected_platform": "debian", "greeting_platform": "debian", "authenticated_greeting": "debian",
		"detected_family": "debian", "detected_os_id": "debian", "detected_os_version": "12.8",
		"detected_virt": "vm", "detected_container_access": "ok", "detected_guests": 3, "detected_graphical": false,
		"detected_services": []any{"docker", "nginx"}, "services_checked_at": 1764000000, "detection_state": "detected",
		"platform_checked_at": 1764000000.5, "role_override": "web",
	}, {
		"detected_family": "klingon", "detected_os_id": "Not An Id!", "detected_virt": "hologram",
		"detected_container_access": "maybe", "detected_guests": 10000, "detected_graphical": "yes",
		"detection_state": "pending", "platform_checked_at": true, "authenticated_greeting": "atari",
		"role_override": "spaceship",
	}, {
		"role_override": "auto", "authenticated_greeting": "", "detection_state": "unavailable",
	}}
	for i, f := range facts {
		p := profiles[i].(map[string]any)
		maps.Copy(p, f)
	}
	out, err := json.Marshal(doc, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
}

// RS4-08, the way back of spec 8.3 with the Python release itself: after
// the Go migration of each golden DATA_DIR and a second Go start, the
// Python release on the same DATA_DIR shows the same settings and saved
// hosts and opens the same SSH keys and TOTP secrets as on an untouched
// copy.
func TestBuildWayBackToPython(t *testing.T) {
	python := pythonBinary(t)
	for _, fx := range k10Fixtures {
		t.Run(fx.name, func(t *testing.T) {
			dir := extractGolden(t, fx.archive)
			pristine := extractGolden(t, fx.archive)
			_, lookup := k10Env(t, dir)
			log := slog.New(slog.DiscardHandler)
			cfg, err := bootstrapConfig(lookup, log)
			if err != nil {
				t.Fatal(err)
			}
			for range 2 {
				st, err := startMigration(t.Context(), cfg, lookup, log)
				if err != nil {
					t.Fatal(err)
				}
				if err := st.Close(); err != nil {
					t.Fatal(err)
				}
			}
			secret := goldenSecret(t)
			got, want := runPython(t, python, pythonSecrets, dir, secret), runPython(t, python, pythonSecrets, pristine, secret)
			if got != want {
				t.Fatalf("the Python release reads other data after the migration:\n got %s\nwant %s", got, want)
			}
			_, compared, ok := strings.Cut(got, "--secrets--")
			if !ok || strings.Count(compared, ": \"") == 0 {
				t.Fatal("no secrets compared")
			}
			t.Logf("%d secrets compared", strings.Count(compared, ": \""))
		})
	}
}
