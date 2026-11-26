package main

import (
	"encoding/json/jsontext"
	"testing"

	"github.com/bifrost0x/webssh/internal/config"
	"github.com/bifrost0x/webssh/internal/migrate/legacy"
)

func TestRecordPort(t *testing.T) {
	for raw, want := range map[string]int{`22`: 22, `2222`: 2222, `65535`: 65535, `0`: 0, `65536`: 0, `"22"`: 0,
		`22.5`: 0, `null`: 0, ``: 0, `-1`: 0} {
		if got := recordPort(jsontext.Value(raw)); got != want {
			t.Errorf("recordPort(%q) = %d, want %d", raw, got, want)
		}
	}
}

func TestEnvSwitchFollowsPython(t *testing.T) {
	look := lookupMap(map[string]string{"A": " TRUE ", "B": "yes", "C": "  ", "D": "false"})
	for name, want := range map[string]bool{"A": true, "B": false, "C": true, "D": false, "MISSING": true} {
		if got := envSwitch(look, name, true); got != want {
			t.Errorf("envSwitch(%s) = %v, want %v", name, got, want)
		}
	}
	if envFlag(look, "A") {
		t.Error("envFlag does not strip, like os.environ.get(...).lower() == 'true'")
	}
}

func TestSettingsEnvironmentDefaults(t *testing.T) {
	env := settingsEnvironment(config.Config{}, lookupMap(map[string]string{"AUTOMATION_ENABLED": "true"}))
	if !env.Values["TMUX_ENABLED"] || env.Values["TMUX_DEFAULT"] || !env.Values["AUTOMATION_ENABLED"] || env.Values["SFTP_CHMOD_ENABLED"] {
		t.Errorf("values %v", env.Values)
	}
}

func TestPreviewNotice(t *testing.T) {
	signIn := previewNotice(true)
	if signIn.Enabled || len(signIn.Unavailable) != 0 {
		t.Errorf("sign-in notice %+v", signIn)
	}
	work := previewNotice(false)
	if !work.Enabled || len(work.Unavailable) < 5 {
		t.Errorf("workspace notice %+v", work)
	}
}

func TestIsProbe(t *testing.T) {
	for path, want := range map[string]bool{"/health": true, "/ready": true, "/webssh/ready": true, "/login": false, "/readyx": false} {
		if got := isProbe("/webssh", path); got != want {
			t.Errorf("isProbe(%s) = %v", path, got)
		}
	}
}

type warnings struct{ events [][]any }

func (w *warnings) SecurityWarning(event string, kv ...any) {
	w.events = append(w.events, append([]any{event}, kv...))
}

func TestAuditMigrationNamesSealedPlaintextKeys(t *testing.T) {
	var w warnings
	auditMigration(&w, nil)
	auditMigration(&w, &legacy.Startup{})
	st := &legacy.Startup{Migrated: true, Report: &legacy.Report{Entities: []legacy.StepReport{
		{Entity: "E23", Warnings: []legacy.Warning{{Code: plaintextKeySealed, UserID: 3, Count: 1}, {Code: "other"}}},
	}}}
	auditMigration(&w, st)
	if len(w.events) != 1 || w.events[0][0] != "MIGRATION_PLAINTEXT_KEY_SEALED" || w.events[0][4] != int64(3) || w.events[0][6] != 1 {
		t.Fatalf("events %v", w.events)
	}
}
