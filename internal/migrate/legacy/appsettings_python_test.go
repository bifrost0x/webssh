package legacy

import (
	"bytes"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bifrost0x/webssh/internal/oracletest"
	"github.com/bifrost0x/webssh/internal/pyjson"
	"github.com/bifrost0x/webssh/internal/settings"
)

// Differential test of the start-up migrations of app_settings.json
// (CONDITIONS D2): migrate_runtime_features, then migrate_feature_policies,
// as app/__init__.py runs them, against migrateRuntimeFeatures and
// migrateFeaturePolicies for the same document and environment. Revisions
// are random on both sides, so a generated one compares as "generated".
// The Python answers are recorded in testdata/python_appsettings.json.
const pythonAppSettings = `
import json, sys
from pathlib import Path
import config
from app import app_settings as s
spec = json.load(sys.stdin)
out = []
for i, c in enumerate(spec):
    path = Path(c["dir"]) / ("app_settings_%d.json" % i)
    if c["doc"] is not None:
        path.write_text(c["doc"], encoding="utf-8")
    s._SETTINGS_FILE = path
    s._cached_document = None
    config.EXPLICIT_ENVIRONMENT_KEYS = frozenset(k for k, v in c["explicit"].items() if v)
    for key, value in c["values"].items():
        setattr(config, key, value)
    s.migrate_runtime_features()
    s.migrate_feature_policies(automation_enabled=config.AUTOMATION_ENABLED, credentials_enabled=c["vaults"])
    out.append(path.read_text(encoding="utf-8") if path.exists() else None)
sys.stdout.write("\n--result--\n" + json.dumps(out))
`

type appSettingsCase struct {
	Dir      string          `json:"dir"`
	Doc      *string         `json:"doc"`
	Explicit map[string]bool `json:"explicit"`
	Values   map[string]bool `json:"values"`
	Vaults   bool            `json:"vaults"`
}

func appSettingsCases(dir string) []appSettingsCase {
	docs := []*string{nil}
	for _, d := range []string{
		`{"schema_version": 2}`,
		`{"schema_version": 2, "tmux_enabled": false, "credentials_enabled": true, "credentials_enabled_revision": "c0"}`,
		`{"schema_version": 2, "tmux_enabled": true, "runtime_feature_migration": ["tmux_enabled"], "automation_enabled": false, "automation_enabled_revision": "a0", "automation_effective_observed": false}`,
		`{"schema_version": 2, "sftp_chmod_enabled": true, "runtime_feature_migration": [], "automation_enabled": true, "automation_enabled_revision": "a0", "automation_enabled_from_environment": true, "automation_effective_observed": true}`,
		`{"schema_version": 2, "server_operations_enabled": false, "runtime_feature_migration": ["server_operations_enabled", "tmux_default"], "tmux_default": true, "automation_enabled": true, "automation_enabled_revision": "a0", "automation_enabled_from_environment": false, "credentials_enabled": false, "credentials_enabled_revision": "c0"}`,
		`{"schema_version": 2, "automation_enabled": true, "automation_enabled_revision": "a0"}`,
		`{"schema_version": 2, "runtime_feature_migration": ["tmux_enabled", "tmux_enabled", "tmux_default"], "tmux_default": false}`,
		`{"schema_version": 2, "automation_enabled": false, "automation_enabled_revision": "a0", "automation_enabled_from_environment": true, "automation_effective_observed": true, "credentials_enabled": true}`,
		`{"schema_version": 2, "support_links_enabled": false, "registration_enabled": true, "tmux_enabled": false, "tmux_default": true, "sftp_chmod_enabled": false, "server_operations_enabled": true, "runtime_feature_migration": ["sftp_chmod_enabled", "server_operations_enabled"], "automation_enabled": false, "automation_enabled_revision": "a0", "automation_effective_observed": false, "automation_enabled_from_environment": false}`,
	} {
		docs = append(docs, &d)
	}
	envs := []struct{ explicit, values map[string]bool }{
		{map[string]bool{}, map[string]bool{"AUTOMATION_ENABLED": false, "TMUX_ENABLED": false, "TMUX_DEFAULT": false, "SFTP_CHMOD_ENABLED": false, "SERVER_OPERATIONS_ENABLED": false}},
		{map[string]bool{"TMUX_ENABLED": true, "AUTOMATION_ENABLED": true}, map[string]bool{"AUTOMATION_ENABLED": true, "TMUX_ENABLED": true, "TMUX_DEFAULT": false, "SFTP_CHMOD_ENABLED": false, "SERVER_OPERATIONS_ENABLED": false}},
		{map[string]bool{"TMUX_ENABLED": true, "TMUX_DEFAULT": true, "SERVER_OPERATIONS_ENABLED": true, "SFTP_CHMOD_ENABLED": true, "AUTOMATION_ENABLED": true},
			map[string]bool{"AUTOMATION_ENABLED": false, "TMUX_ENABLED": false, "TMUX_DEFAULT": true, "SFTP_CHMOD_ENABLED": true, "SERVER_OPERATIONS_ENABLED": true}},
		{map[string]bool{"AUTOMATION_ENABLED": false}, map[string]bool{"AUTOMATION_ENABLED": true, "TMUX_ENABLED": true, "TMUX_DEFAULT": true, "SFTP_CHMOD_ENABLED": false, "SERVER_OPERATIONS_ENABLED": false}},
	}
	var out []appSettingsCase
	for _, d := range docs {
		for _, e := range envs {
			for _, v := range []bool{false, true} {
				out = append(out, appSettingsCase{Dir: dir, Doc: d, Explicit: e.explicit, Values: e.values, Vaults: v})
			}
		}
	}
	return out
}

// appSettingsInput is the input document of a case as a map.
func appSettingsInput(c appSettingsCase) map[string]any {
	input := map[string]any{}
	if c.Doc != nil {
		_ = json.Unmarshal([]byte(*c.Doc), &input)
	}
	return input
}

// normalise parses a document, drops schema_version (the step always
// writes it) and marks revisions that are not in the input as generated.
func normaliseAppSettings(t *testing.T, doc string, input map[string]any) string {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(doc), &m); err != nil {
		t.Fatalf("%v: %s", err, doc)
	}
	delete(m, "schema_version")
	for _, name := range []string{"credentials_enabled_revision", "automation_enabled_revision"} {
		if v, ok := m[name]; ok && v != input[name] {
			m[name] = "generated"
		}
	}
	b, _ := json.Marshal(m, json.Deterministic(true))
	return string(b)
}

func TestAppSettingsStartupMigrationsMatchPython(t *testing.T) {
	t.Parallel()
	cases := appSettingsCases("")
	rec := oracletest.Open(t, "testdata/python_appsettings.json")
	want := oracletest.Ask(t, rec, "startup_migrations", cases, func(r oracletest.Release) []*string {
		dir := t.TempDir()
		in, _ := json.Marshal(appSettingsCases(dir))
		cmd := exec.CommandContext(t.Context(), r.Python, "-c", pythonAppSettings) // #nosec G204 -- test oracle
		cmd.Dir = r.Root
		cmd.Env = append(os.Environ(), "DATA_DIR="+filepath.Join(dir, "data"), "SECRET_KEY=differential-test-only-0123456789abcdef", "PYTHONDONTWRITEBYTECODE=1")
		cmd.Stdin = bytes.NewReader(in)
		raw, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("python: %v\n%s", err, raw)
		}
		_, result, ok := strings.Cut(string(raw), "\n--result--\n")
		if !ok {
			t.Fatalf("python output: %s", raw)
		}
		var docs []*string
		if err := json.Unmarshal([]byte(result), &docs); err != nil {
			t.Fatal(err)
		}
		if len(docs) != len(cases) {
			t.Fatalf("%d results for %d cases", len(docs), len(cases))
		}
		// Revisions are random; the normalised form compares them as
		// "generated".
		for i, c := range cases {
			if docs[i] != nil {
				norm := normaliseAppSettings(t, *docs[i], appSettingsInput(c))
				docs[i] = &norm
			}
		}
		return docs
	})
	for i, c := range cases {
		input := appSettingsInput(c)
		members := []pyjson.Member{}
		if c.Doc != nil {
			members, _ = pyjson.Members(jsontext.Value(*c.Doc))
		}
		env := settings.Environment{Values: c.Values, Explicit: c.Explicit}
		members = migrateRuntimeFeatures(members, env)
		members, generated := migrateFeaturePolicies(members, env, c.Vaults)
		got := normaliseAppSettings(t, string(pyjson.Object(members)), input)
		if want[i] == nil {
			t.Fatalf("case %d: Python wrote no file", i)
		}
		if exp := *want[i]; got != exp {
			t.Errorf("case %d (doc %v, env %v %v, vaults %v):\n got %s\nwant %s", i, c.Doc != nil, c.Explicit, c.Values, c.Vaults, got, exp)
		}
		for _, name := range generated {
			if !strings.Contains(got, `"`+name+`":"generated"`) {
				t.Errorf("case %d: %s reported generated but kept", i, name)
			}
		}
	}
}
