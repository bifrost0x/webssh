package legacy

import (
	json "encoding/json/v2"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// findItem returns the item of a list with the given field value.
func findItem(items []any, field string, value any) map[string]any {
	for _, it := range items {
		if m, ok := it.(map[string]any); ok && reflect.DeepEqual(m[field], value) {
			return m
		}
	}
	return nil
}

// assertSubset checks that every field of want has the same value in got.
func assertSubset(t *testing.T, what string, got map[string]any, want map[string]any) {
	t.Helper()
	if got == nil {
		t.Errorf("%s: missing", what)
		return
	}
	for k, v := range want {
		if !reflect.DeepEqual(got[k], v) {
			t.Errorf("%s: %s = %#v, want %#v", what, k, got[k], v)
		}
	}
}

func TestGoldenUserStores(t *testing.T) {
	t.Parallel()
	docs, err := golden.source.UserDocuments(goldenUserByName(t, "local_user").ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, spec := range userStores {
		if _, ok := docs[spec.name]; !ok {
			t.Errorf("store %s not read", spec.name)
		}
	}
	v := golden.manifest.Values
	edge := v.EdgeCases
	conn := v.Connections
	for name, p := range conn["profiles"].(map[string]any) {
		assertSubset(t, "profile "+name, findItem(docs["profiles"].Items, "name", name), p.(map[string]any))
	}
	for _, c := range []struct{ store, key string }{{"jump_hosts", "jump_host"}, {"socks_proxies", "socks_proxy"}, {"smb_shares", "smb_share"}} {
		want := conn[c.key].(map[string]any)
		assertSubset(t, c.key, findItem(docs[c.store].Items, "id", want["id"]), want)
	}
	if findItem(docs["profiles"].Items, "id", edge.Profiles.Deleted) != nil {
		t.Error("deleted profile present")
	}
	for _, id := range []string{edge.Profiles.Minimal, edge.Profiles.Unicode} {
		if findItem(docs["profiles"].Items, "id", id) == nil {
			t.Errorf("profile %s missing", id)
		}
	}
	if p := findItem(docs["profiles"].Items, "id", edge.Profiles.LongName); p == nil || p["name"] != edge.Profiles.StoredLongName {
		t.Errorf("long-name profile: %v", p)
	}
	for _, r := range []struct{ store, key string }{{"jump_hosts", "deleted_jump_host"}, {"smb_shares", "deleted_smb"}} {
		if findItem(docs[r.store].Items, "id", edge.Routes[r.key]) != nil {
			t.Errorf("%s present", r.key)
		}
	}
	for _, r := range []struct{ store, key string }{{"socks_proxies", "socks_with_auth"}, {"smb_shares", "smb_unicode_empty_domain"}} {
		if findItem(docs[r.store].Items, "id", edge.Routes[r.key]) == nil {
			t.Errorf("%s missing", r.key)
		}
	}
	for _, set := range v.Commands["command_sets"].([]any) {
		want := set.(map[string]any)
		assertSubset(t, "command set", findItem(docs["command_sets"].Items, "id", want["id"]), want)
	}
	cmd := v.Commands["user_command"].(map[string]any)
	assertSubset(t, "user command", findItem(docs["commands"].Items, "id", cmd["id"]), cmd)
	for key, present := range map[string]bool{"unicode_command": true, "deleted_command": false} {
		if (findItem(docs["commands"].Items, "id", edge.Commands[key]) != nil) != present {
			t.Errorf("%s present = %v", key, !present)
		}
	}
	for key, present := range map[string]bool{"unicode_set": true, "deleted_set": false} {
		if (findItem(docs["command_sets"].Items, "id", edge.Commands[key]) != nil) != present {
			t.Errorf("%s present = %v", key, !present)
		}
	}
	runbook := v.Automation["runbook"].(map[string]any)
	assertSubset(t, "runbook", findItem(docs["automation"].Items, "id", runbook["id"]), runbook)
	if findItem(docs["automation"].Items, "id", edge.Automation["deleted_runbook"]) != nil {
		t.Error("deleted runbook present")
	}
	run := edge.Automation["run_history"].(map[string]any)
	assertSubset(t, "run history", findItem(docs["automation_runs"].Items, "id", run["id"]), run)
	assertSubset(t, "settings", docs["settings"].Object, v.UserSettings)
	if len(docs["host_context"].Entries) == 0 {
		t.Error("host context has no hosts")
	}
	for _, h := range docs["host_context"].Entries {
		host := h.(map[string]any)
		for _, field := range []string{"notes", "directories", "command_sets"} {
			if !reflect.DeepEqual(host[field], edge.HostContext[field]) {
				t.Errorf("host context %s differs", field)
			}
		}
	}
}

func TestGoldenSchedules(t *testing.T) {
	t.Parallel()
	schedules, err := golden.source.Schedules(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	enabled := map[any]bool{}
	for _, s := range schedules {
		var grant map[string]any
		if err := json.Unmarshal([]byte(s.Grant), &grant); err != nil {
			t.Fatalf("schedule %s: grant: %v", s.ID, err)
		}
		enabled[s.ID] = s.Enabled
		if s.ID == golden.manifest.Values.Automation["schedule_id"] {
			book := grant["book"].(map[string]any)
			if book["id"] != golden.manifest.Values.Automation["runbook"].(map[string]any)["id"] {
				t.Errorf("schedule grant runbook %v", book["id"])
			}
		}
	}
	if !enabled[golden.manifest.Values.Automation["schedule_id"]] || enabled[golden.manifest.Values.EdgeCases.Automation["paused_schedule"]] {
		t.Fatalf("schedules %v", enabled)
	}
}

func TestGoldenGlobalFiles(t *testing.T) {
	t.Parallel()
	settings, err := golden.source.AppSettings()
	if err != nil {
		t.Fatal(err)
	}
	// edge_cases.admin_settings.support_links_enabled is [before, after].
	if change := golden.manifest.Values.EdgeCases.AdminSettings["support_links_enabled"]; settings.Version != 2 ||
		len(change) != 2 || settings.Object["support_links_enabled"] != change[1] {
		t.Errorf("app settings %v", settings.Object)
	}
	quarantine, err := golden.source.QuarantinedAccounts()
	edge := golden.manifest.Values.EdgeCases.DeletedAccount
	if err != nil || !slices.Contains(quarantine, edge.QuarantineDir[len("deleted_users/"):]) {
		t.Fatalf("quarantined accounts %v, %v", quarantine, err)
	}
	if _, err := golden.source.readStore(edge.QuarantineDir+"/profiles.json", userStores[0]); err != nil {
		t.Fatalf("quarantined profiles: %v", err)
	}
	logs, err := golden.source.LogFiles()
	var wantLogs []string
	for _, f := range golden.manifest.Files {
		if rest, ok := strings.CutPrefix(f.Path, "data/"); ok && strings.HasPrefix(rest, "logs/") {
			wantLogs = append(wantLogs, rest)
		}
	}
	if err != nil || !slices.Equal(logs, wantLogs) {
		t.Fatalf("log files %v, %v", logs, err)
	}
}
