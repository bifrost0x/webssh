package legacy

import (
	"context"
	"encoding/json/jsontext"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bifrost0x/webssh/internal/commands"
	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/hostops"
	"github.com/bifrost0x/webssh/internal/hosts"
	"github.com/bifrost0x/webssh/internal/pyjson"
	"github.com/bifrost0x/webssh/internal/store"
)

func commandsM1Registry(t *testing.T, m M1) *Registry {
	t.Helper()
	r := m1Registry(t, m)
	if err := AddCommands(r); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestAddCommandsTakesOverThePendingEntities(t *testing.T) {
	t.Parallel()
	r := commandsM1Registry(t, M1{})
	for _, c := range r.coverage() {
		if (c.Entity == "E26" || c.Entity == "E27") && c.Kind != CoverStep {
			t.Errorf("%s is %s", c.Entity, c.Kind)
		}
	}
	if len(r.Uncovered()) != 0 {
		t.Fatalf("uncovered %v", r.Uncovered())
	}
	if err := AddCommands(r); err == nil {
		t.Fatal("registering the steps twice must fail")
	}
}

func migrateWithCommands(t *testing.T, dataDir string) migrated {
	t.Helper()
	before := legacySnapshot(t, dataDir)
	o := testOptions(t, dataDir)
	o.Registry = commandsM1Registry(t, M1{AdminUsers: []string{"cfg_admin"}, Persistent: &testPersistent{}})
	o.Secret = golden.manifest.SecretKey.Value
	st, err := startClosed(o)
	if err != nil || !st.Migrated {
		t.Fatalf("migration: %+v, %v", st, err)
	}
	assertUntouched(t, dataDir, before)
	return openMigrated(t, dataDir, o.Secret, st.Report)
}

func legacyRecords(t *testing.T, dir, file, key string) []jsontext.Value {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "users", "user_3", file))
	if err != nil {
		t.Fatal(err)
	}
	doc, _, err := pyjson.Load(raw)
	if err != nil {
		t.Fatal(err)
	}
	if key != "" {
		doc, _ = pyjson.Get(doc, key)
	}
	items, _ := pyjson.Items(doc)
	return items
}

// goldenRefs lists the migrated saved hosts that refer to a set or a
// command, as the provider in cmd/webssh does.
type goldenRefs struct{ db *store.DB }

func (g goldenRefs) find(ctx context.Context, owner int64, field, id string) ([]commands.Usage, error) {
	var out []commands.Usage
	err := g.db.Read(ctx, func(tx *store.Tx) error {
		l, err := hosts.Export(ctx, tx, owner)
		for _, p := range l.Profiles {
			v, _ := pyjson.Get(p, field)
			if s, _ := pyString(v); s == id {
				out = append(out, commands.Usage{Name: "golden", Type: "profile"})
			}
		}
		return err
	})
	return out, err
}

func (g goldenRefs) SetUsages(ctx context.Context, owner int64, id string) ([]commands.Usage, error) {
	return g.find(ctx, owner, "command_set_id", id)
}

func (g goldenRefs) CommandUsages(ctx context.Context, owner int64, id string) ([]commands.Usage, error) {
	return g.find(ctx, owner, "command_id", id)
}

type goldenProfiles struct{ db *store.DB }

func (p goldenProfiles) ProfileIDs(ctx context.Context, owner int64) ([]string, error) {
	return (&hosts.Service{DB: p.db}).ProfileIDs(ctx, owner)
}

// E26, E27 and the set references of E28 against the Golden Data Set:
// the records arrive byte for byte, the Unicode command and set resolve
// as in Python, the parameterised set resolves its values as Python does,
// a set a saved host starts with cannot be deleted, and the host
// context's reference names a migrated set.
func TestCommandsGolden(t *testing.T) {
	dir := copyGolden(t)
	wantCommands := legacyRecords(t, dir, "commands.json", "")
	wantSets := legacyRecords(t, dir, "command_sets.json", "command_sets")
	m := migrateWithCommands(t, dir)
	ctx := t.Context()
	var gotCommands, gotSets []jsontext.Value
	if err := m.db.Read(ctx, func(tx *store.Tx) error {
		var err error
		gotCommands, gotSets, err = commands.StoredTx(ctx, tx, 3)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if !sameRecords(gotCommands, wantCommands) || len(gotCommands) != 2 {
		t.Fatalf("commands\n got %s\nwant %s", gotCommands, wantCommands)
	}
	if !sameRecords(gotSets, wantSets) || len(gotSets) != 3 {
		t.Fatalf("sets\n got %s\nwant %s", gotSets, wantSets)
	}
	for _, e := range []string{"E26", "E27"} {
		for _, p := range m.report.Pending {
			if p.Entity == e {
				t.Errorf("%s still pending: %+v", e, p)
			}
		}
	}

	lib := &commands.Library{DB: m.db, Refs: goldenRefs{m.db}}
	ids := golden.manifest.Values.EdgeCases.Commands
	text, params, err := lib.Command(ctx, 3, ids["unicode_command"])
	if err != nil || text != `printf "%s\n" "ünïcødé"` || params != "" {
		t.Fatalf("Unicode command %q %q %v", text, params, err)
	}
	if got, err := lib.Resolve(ctx, 3, ids["unicode_set"], nil, false); err != nil || got != `printf "%s\n" "ünïcødé"` {
		t.Fatalf("Unicode set %q %v", got, err)
	}
	// The answers of app/command_parameters.py for these values.
	paramSet := "5ba6f43d-d5c7-4422-b297-c5a32f3ba1eb"
	for _, c := range []struct {
		value, want string
		sudo        bool
	}{
		{"/srv/ünïcødé dir", `'ls' -la '/srv/ünïcødé dir'`, false},
		{"/var/log", `sudo 'ls' -la /var/log`, true},
	} {
		got, err := lib.Resolve(ctx, 3, paramSet, map[string]string{"path": c.value}, c.sudo)
		if err != nil || got != c.want {
			t.Errorf("parameterised set: %q %v, Python %q", got, err, c.want)
		}
	}
	if _, err := lib.Resolve(ctx, 3, paramSet, nil, false); !fault.Is(err, fault.ValidationError) {
		t.Errorf("parameterised set without values: %v", err)
	}
	if _, err := lib.Resolve(ctx, 3, ids["deleted_set"], nil, false); !fault.Is(err, fault.NotFound) {
		t.Errorf("deleted set: %v", err)
	}
	if _, _, err := lib.Command(ctx, 3, ids["deleted_command"]); !fault.Is(err, fault.NotFound) {
		t.Errorf("deleted command: %v", err)
	}
	if _, err := lib.Resolve(ctx, 4, ids["unicode_set"], nil, false); !fault.Is(err, fault.NotFound) {
		t.Errorf("another user's set: %v", err)
	}

	bootstrap := "867426f3-ca2f-40df-837c-6430d34fa3c9"
	_, err = lib.DeleteSet(ctx, 3, jsontext.Value(`"`+bootstrap+`"`))
	if !fault.Is(err, fault.InUse) || fault.DetailsOf(err)["usages"] == nil {
		t.Fatalf("delete of the set a saved host starts with: %v", err)
	}
	if ok, err := lib.SetExists(ctx, 3, bootstrap); err != nil || !ok {
		t.Fatalf("SetExists %v %v", ok, err)
	}

	// E28: the host context keeps its reference and saves with it.
	contexts := &hostops.Contexts{DB: m.db, Profiles: goldenProfiles{m.db}, Sets: lib}
	profile := "1bd77053-ce70-4437-9be1-c35f332d2f4c"
	hc, err := contexts.Read(ctx, 3, profile)
	if err != nil || len(hc.CommandSets) != 1 || hc.CommandSets[0] != bootstrap {
		t.Fatalf("host context %+v %v", hc, err)
	}
	if _, err := contexts.Write(ctx, 3, profile, hc.Content, hc.Revision); err != nil {
		t.Fatalf("saving the migrated context: %v", err)
	}
	stale := hc.Content
	stale.CommandSets = []string{ids["deleted_set"]}
	var ce *hostops.ContextError
	if _, err := contexts.Write(ctx, 3, profile, stale, hc.Revision+1); !errors.As(err, &ce) || ce.Code != "invalid_reference" {
		t.Fatalf("reference to a deleted set: %v", err)
	}
}

// A store Python refuses to read stops the migration (STOP).
func TestCommandsInvalidDocumentStops(t *testing.T) {
	for name, c := range map[string]struct {
		file, from, to string
	}{
		"command without text": {"commands.json", `"command": "uptime",`, `"command": 5,`},
		"float user id":        {"commands.json", `"userId": 3,`, `"userId": 3.0,`},
		"step of unknown type": {"command_sets.json", `"type": "inline",`, `"type": "shell",`},
		"interpreter in argv":  {"command_sets.json", `"ls",`, `"bash",`},
	} {
		t.Run(name, func(t *testing.T) {
			dir := copyGolden(t)
			path := filepath.Join(dir, "users", "user_3", c.file)
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			changed := strings.Replace(string(raw), c.from, c.to, 1)
			if changed == string(raw) {
				t.Fatal("the edit did not apply")
			}
			writeLegacyFile(t, dir, "users/user_3/"+c.file, changed)
			o := testOptions(t, dir)
			o.Registry = commandsM1Registry(t, M1{AdminUsers: []string{"cfg_admin"}, Persistent: &testPersistent{}})
			o.Secret = golden.manifest.SecretKey.Value
			_, err = startClosed(o)
			entity := "E26"
			if c.file == "command_sets.json" {
				entity = "E27"
			}
			stop := assertStop(t, err, entity)
			if !errors.Is(stop, commands.ErrInvalidRecord) {
				t.Errorf("cause %v", stop)
			}
			assertNoGoDatabase(t, dir)
		})
	}
}

// The legacy object form of commands.json is read like a list.
func TestCommandsLegacyWrapper(t *testing.T) {
	dir := copyGolden(t)
	want := legacyRecords(t, dir, "commands.json", "")
	writeLegacyFile(t, dir, "users/user_3/commands.json", `{"schema_version": 2, "commands": `+string(pyjson.Array(want))+`}`)
	m := migrateWithCommands(t, dir)
	var got []jsontext.Value
	if err := m.db.Read(t.Context(), func(tx *store.Tx) error {
		var err error
		got, _, err = commands.StoredTx(t.Context(), tx, 3)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if !sameRecords(got, want) {
		t.Fatalf("got %s", got)
	}
}
