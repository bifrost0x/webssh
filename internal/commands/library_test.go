package commands_test

import (
	"context"
	"encoding/json/jsontext"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/commands"
	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/pyjson"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
	"github.com/bifrost0x/webssh/internal/store"
	"github.com/bifrost0x/webssh/internal/store/storetest"
)

func newLibrary(t *testing.T, r refs) *commands.Library {
	t.Helper()
	n := 0
	return &commands.Library{
		DB: storetest.Open(t, commands.Schema()), Refs: r,
		Now: func() time.Time { return time.Date(2026, 11, 27, 9, 0, 0, 250000000, time.UTC) },
		NewID: func() string {
			n++
			return fmt.Sprintf("id-%d", n)
		},
	}
}

func str(s string) jsontext.Value { return pyjson.String(s) }

func member(t *testing.T, v jsontext.Value, name string) string {
	t.Helper()
	m, ok := pyjson.Get(v, name)
	if !ok {
		return "<absent>"
	}
	return string(m)
}

func addCommand(t *testing.T, l *commands.Library, user int64, name, command string) jsontext.Value {
	t.Helper()
	rec, err := l.Add(t.Context(), user, protocol.CommandSave{Name: str(name), Command: str(command), Description: str("d")})
	if err != nil {
		t.Fatal(err)
	}
	return rec
}

func TestCommandLifecycle(t *testing.T) {
	t.Parallel()
	l := newLibrary(t, refs{})
	ctx := t.Context()
	rec := addCommand(t, l, 1, "Uptime ✓", "uptime")
	want := `{"id":"id-1","name":"Uptime ✓","command":"uptime","parameters":"","description":"d","os":["all"],` +
		`"category":"custom","isSystem":false,"userId":1,"createdAt":"2026-11-27T09:00:00.250000"}`
	if string(rec) != want {
		t.Fatalf("added\n got %s\nwant %s", rec, want)
	}
	list, err := l.List(ctx, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	system, _ := commands.SystemCommands()
	if len(list) != len(system)+1 || len(system) != 312 {
		t.Fatalf("list has %d entries, %d built in", len(list), len(system))
	}
	if member(t, list[0], "isSystem") != "true" || member(t, list[0], "userId") != "null" {
		t.Errorf("built-in template %s", list[0])
	}
	if other, _ := l.List(ctx, 2, nil); len(other) != len(system) {
		t.Errorf("another user sees %d entries", len(other))
	}
	windows, _ := l.List(ctx, 1, str("WINDOWS"))
	for _, c := range windows {
		if !strings.Contains(member(t, c, "os"), `"windows"`) && !strings.Contains(member(t, c, "os"), `"all"`) {
			t.Fatalf("filtered entry %s", c)
		}
	}
	if _, err := l.List(ctx, 1, jsontext.Value("5")); !fault.Is(err, fault.ValidationError) {
		t.Errorf("filter that is not text: %v", err)
	}

	upd, err := l.Update(ctx, 1, protocol.CommandSave{CommandID: str("id-1"), Name: str("Up"), Command: str("uptime -p"),
		Description: str("d2"), OS: jsontext.Value(`["linux"]`), Category: str("")})
	if err != nil {
		t.Fatal(err)
	}
	if member(t, upd, "createdAt") != `"2026-11-27T09:00:00.250000"` || member(t, upd, "category") != `"custom"` ||
		member(t, upd, "os") != `["linux"]` {
		t.Errorf("updated %s", upd)
	}
	for name, req := range map[string]protocol.CommandSave{
		"missing description": {Name: str("n"), Command: str("c")},
		"name not text":       {Name: jsontext.Value("5"), Command: str("c"), Description: str("d")},
		"os not a list":       {Name: str("n"), Command: str("c"), Description: str("d"), OS: str("linux")},
		"name too large":      {Name: str(strings.Repeat("x", 513)), Command: str("c"), Description: str("d")},
	} {
		if _, err := l.Add(ctx, 1, req); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := l.Update(ctx, 2, protocol.CommandSave{CommandID: str("id-1"), Name: str("x"), Command: str("x"), Description: str("x")}); !fault.Is(err, fault.NotFound) {
		t.Errorf("update of another user's command: %v", err)
	}
	if _, err := l.Delete(ctx, 2, str("id-1")); !fault.Is(err, fault.NotFound) {
		t.Errorf("delete of another user's command: %v", err)
	}
	if id, err := l.Delete(ctx, 1, str("id-1")); err != nil || id != "id-1" {
		t.Fatalf("delete %q %v", id, err)
	}
}

func TestCommandQuota(t *testing.T) {
	t.Parallel()
	l := newLibrary(t, refs{})
	l.Limits = commands.Limits{MaxCommands: 10}
	for i := range 10 {
		addCommand(t, l, 1, fmt.Sprint(i), "true")
	}
	_, err := l.Add(t.Context(), 1, protocol.CommandSave{Name: str("x"), Command: str("x"), Description: str("x")})
	if !fault.Is(err, fault.QuotaExceeded) || !strings.Contains(messageOf(err), "more than 10 records") {
		t.Fatalf("eleventh command: %v", err)
	}
	l.Limits = commands.Limits{StoreMaxBytes: 2048}
	_, err = l.Add(t.Context(), 1, protocol.CommandSave{Name: str("x"), Command: str("x"), Description: str("x")})
	if !fault.Is(err, fault.QuotaExceeded) {
		t.Fatalf("store over its byte limit: %v", err)
	}
}

func saveSet(t *testing.T, l *commands.Library, user int64, body string) (jsontext.Value, error) {
	t.Helper()
	var req protocol.CommandSetSave
	if err := protocol.DecodePayload(jsontext.Value(body), &req); err != nil {
		t.Fatal(err)
	}
	return l.SaveSet(t.Context(), user, req)
}

func TestSetLifecycleAndReferences(t *testing.T) {
	t.Parallel()
	r := refs{}
	l := newLibrary(t, r)
	ctx := t.Context()
	addCommand(t, l, 1, "List", "ls")
	set, err := saveSet(t, l, 1, `{"name":" Deploy ","use_sudo":true,"steps":[{"type":"inline","command":"cd /srv\r\nmake # build"},{"type":"library","command_id":"id-1","parameters_override":"-la"},{"type":"inline","command":"# done"}]}`)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"id":"id-2","name":"Deploy","description":"","use_sudo":true,"steps":[{"type":"inline","command":"cd /srv\nmake # build"},` +
		`{"type":"library","command_id":"id-1","parameters_override":"-la"},{"type":"inline","command":"# done"}],"parameters":[],` +
		`"created_at":"2026-11-27T09:00:00.250000+00:00","updated_at":"2026-11-27T09:00:00.250000+00:00"}`
	if string(set) != want {
		t.Fatalf("saved\n got %s\nwant %s", set, want)
	}
	text, err := l.Resolve(ctx, 1, "id-2", nil, false)
	if want := "sudo cd /srv\nsudo make && # build\nsudo ls -la && :\n# done"; err != nil || text != want {
		t.Fatalf("resolved %q %v, want %q", text, err, want)
	}
	if _, err := saveSet(t, l, 1, `{"name":"deploy","steps":[{"type":"inline","command":"x"}]}`); !fault.Is(err, fault.ValidationError) {
		t.Errorf("duplicate name: %v", err)
	}
	if _, err := saveSet(t, l, 1, `{"name":"x","steps":[{"type":"library","command_id":"missing"}]}`); err == nil ||
		messageOf(err) != "Command set step 1 references a missing command" {
		t.Errorf("missing command: %v", err)
	}
	if _, err := saveSet(t, l, 1, `{"name":"x"}`); !fault.Is(err, fault.QuotaExceeded) {
		t.Errorf("no steps (Python reports the storage rule): %v", err)
	}
	dup, err := l.DuplicateSet(ctx, 1, str("id-2"))
	if err != nil || member(t, dup, "name") != `"Deploy Copy"` {
		t.Fatalf("duplicate %s %v", dup, err)
	}
	dup2, _ := l.DuplicateSet(ctx, 1, str("id-2"))
	if member(t, dup2, "name") != `"Deploy Copy 2"` {
		t.Errorf("second duplicate %s", dup2)
	}

	sets, err := l.Sets(ctx, 1)
	if err != nil || len(sets) != 3 || member(t, sets[0], "sudo_resolved_command") == "<absent>" {
		t.Fatalf("sets %s %v", sets, err)
	}

	// A command a set uses and a set a saved host starts with stay.
	if _, err := l.Delete(ctx, 1, str("id-1")); !fault.Is(err, fault.InUse) || messageOf(err) != "Command is used by 3 command sets" {
		t.Errorf("delete of a used command: %v", err)
	}
	r["id-2"] = []commands.Usage{{ID: "p1", Name: "web\x00", Type: "profile"}}
	_, err = l.DeleteSet(ctx, 1, str("id-2"))
	if !fault.Is(err, fault.InUse) || messageOf(err) != "Command set is used by 1 profile" {
		t.Fatalf("delete of a used set: %v", err)
	}
	if names := fault.DetailsOf(err)["usages"].([]string); len(names) != 1 || names[0] != "web�" {
		t.Errorf("usages %q", names)
	}
	if _, err := saveSet(t, l, 1, `{"id":"id-2","name":"Deploy","parameters":[{"name":"p"}],"steps":[{"type":"argv","argv":["ls","{{p}}"]}]}`); err == nil ||
		messageOf(err) != "Remove startup profile references before adding command parameters" {
		t.Errorf("parameters on a referenced set: %v", err)
	}
	delete(r, "id-2")
	if _, err := l.DeleteSet(ctx, 2, str("id-2")); !fault.Is(err, fault.NotFound) {
		t.Errorf("delete of another user's set: %v", err)
	}
	if id, err := l.DeleteSet(ctx, 1, str("id-3")); err != nil || id != "id-3" {
		t.Errorf("delete %q %v", id, err)
	}
}

func TestUpdateKeepsUnknownMembers(t *testing.T) {
	t.Parallel()
	l := newLibrary(t, refs{})
	ctx := t.Context()
	if err := l.DB.Write(ctx, func(tx *store.Tx) error {
		return commands.ImportTx(ctx, tx, 1, nil, []jsontext.Value{
			jsontext.Value(`{"future":{"x":1},"id":"s1","name":"Old","steps":[{"type":"inline","command":"a"}],"created_at":"2020-01-01T00:00:00+00:00"}`),
		})
	}); err != nil {
		t.Fatal(err)
	}
	upd, err := saveSet(t, l, 1, `{"id":"s1","name":"New","steps":[{"type":"inline","command":"b"}]}`)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(upd), `{"future":{"x":1},"id":"s1","name":"New"`) || member(t, upd, "created_at") != `"2020-01-01T00:00:00+00:00"` {
		t.Fatalf("updated %s", upd)
	}
}

func TestParameterisedSet(t *testing.T) {
	t.Parallel()
	l := newLibrary(t, refs{})
	ctx := t.Context()
	if _, err := saveSet(t, l, 1, `{"name":"Grep","parameters":[{"name":"pattern"}],"steps":[{"type":"argv","argv":["grep","-r","{{pattern}}","/var/log"]}]}`); err != nil {
		t.Fatal(err)
	}
	got, err := l.ResolveParameters(ctx, 1, str("id-1"), jsontext.Value(`{"pattern":"a'b; rm -rf /"}`), jsontext.Value("true"))
	if want := `sudo 'grep' -r 'a'"'"'b; rm -rf /' /var/log`; err != nil || got != want {
		t.Fatalf("resolved %q %v, want %q", got, err, want)
	}
	for name, values := range map[string]string{"missing": `{}`, "surplus": `{"pattern":"x","other":"y"}`,
		"control": `{"pattern":"a\nb"}`, "not text": `{"pattern":5}`, "not an object": `["x"]`} {
		if _, err := l.ResolveParameters(ctx, 1, str("id-1"), jsontext.Value(values), nil); !fault.Is(err, fault.ValidationError) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := l.ResolveParameters(ctx, 1, str("id-1"), jsontext.Value(`{"pattern":"x"}`), str("yes")); !fault.Is(err, fault.ValidationError) {
		t.Errorf("sudo not a boolean: %v", err)
	}
	if _, err := l.ResolveParameters(ctx, 2, str("id-1"), jsontext.Value(`{"pattern":"x"}`), nil); !fault.Is(err, fault.NotFound) {
		t.Errorf("another user's set: %v", err)
	}
	if _, err := l.Resolve(ctx, 1, "id-1", nil, false); messageOf(err) != "Parameterized command sets require interactive launch after connecting" {
		t.Errorf("startup with a parameterised set: %v", err)
	}
	info, err := l.SetInfo(ctx, 1, "id-1")
	if err != nil || info.Name != "Grep" || len(info.Parameters) != 1 || info.Parameters[0] != "pattern" {
		t.Errorf("info %+v %v", info, err)
	}
	if _, err := saveSet(t, l, 1, `{"name":"Shell","parameters":[{"name":"c"}],"steps":[{"type":"argv","argv":["/bin/sh","-c","{{c}}"]}]}`); err == nil {
		t.Error("an interpreter as the program was accepted")
	}
}

type fakeHosts struct {
	text     string
	assigned string
}

func (f *fakeHosts) LegacyStartup(_ context.Context, _ int64, id string) (string, bool, bool, error) {
	if id != "p1" {
		return "", false, false, fault.New(fault.NotFound, "Profile not found")
	}
	return f.text, true, false, nil
}

func (f *fakeHosts) AssignSet(_ context.Context, _ int64, _, setID string) (jsontext.Value, error) {
	f.assigned = setID
	return jsontext.Value(`{"id":"p1"}`), nil
}

func TestConvertLegacyStartup(t *testing.T) {
	t.Parallel()
	l := newLibrary(t, refs{})
	h := &fakeHosts{text: "cd /srv\nls"}
	l.Hosts = h
	set, profile, err := l.Convert(t.Context(), 1, protocol.CommandSetConvert{ProfileID: str("p1"), Name: str("From host")})
	if err != nil || h.assigned != "id-1" || string(profile) != `{"id":"p1"}` ||
		member(t, set, "steps") != `[{"type":"inline","command":"cd /srv\nls"}]` {
		t.Fatalf("convert %s %s %v", set, profile, err)
	}
	h.text = "  "
	if _, _, err := l.Convert(t.Context(), 1, protocol.CommandSetConvert{ProfileID: str("p1"), Name: str("Other")}); messageOf(err) != "Profile has no legacy startup commands" {
		t.Errorf("blank text: %v", err)
	}
}

func TestStartupReferenceChecks(t *testing.T) {
	t.Parallel()
	l := newLibrary(t, refs{})
	ctx := t.Context()
	addCommand(t, l, 1, "List", "ls")
	if _, err := saveSet(t, l, 1, `{"name":"P","parameters":[{"name":"x"}],"steps":[{"type":"argv","argv":["ls","{{x}}"]}]}`); err != nil {
		t.Fatal(err)
	}
	check := func(fn func(tx *store.Tx) error) error {
		return l.DB.Write(ctx, fn)
	}
	cases := []struct {
		name string
		fn   func(tx *store.Tx) error
		code fault.Code
	}{
		{"own command", func(tx *store.Tx) error { return l.CheckCommandTx(ctx, tx, 1, str("id-1"), nil) }, ""},
		{"built-in template", func(tx *store.Tx) error { return l.CheckCommandTx(ctx, tx, 2, str("sys-001"), nil) }, ""},
		{"another user's command", func(tx *store.Tx) error { return l.CheckCommandTx(ctx, tx, 2, str("id-1"), nil) }, fault.NotFound},
		{"override not text", func(tx *store.Tx) error { return l.CheckCommandTx(ctx, tx, 1, str("id-1"), jsontext.Value("5")) }, fault.ValidationError},
		{"override with NUL", func(tx *store.Tx) error { return l.CheckCommandTx(ctx, tx, 1, str("id-1"), str("a\x00")) }, fault.ValidationError},
		{"parameterised set", func(tx *store.Tx) error { return l.CheckSetTx(ctx, tx, 1, str("id-2")) }, fault.ValidationError},
		{"missing set", func(tx *store.Tx) error { return l.CheckSetTx(ctx, tx, 1, str("nope")) }, fault.NotFound},
	}
	for _, c := range cases {
		err := check(c.fn)
		if (c.code == "" && err != nil) || (c.code != "" && !fault.Is(err, c.code)) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

func messageOf(err error) string {
	if err == nil {
		return ""
	}
	_, _, msg := fault.Status(err)
	return msg
}
