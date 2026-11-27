package legacy

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/bifrost0x/webssh/internal/automation"
	"github.com/bifrost0x/webssh/internal/hosts"
	"github.com/bifrost0x/webssh/internal/principal/principaltest"
	"github.com/bifrost0x/webssh/internal/ssh/client"
	"github.com/bifrost0x/webssh/internal/ssh/hostkey"
	"github.com/bifrost0x/webssh/internal/store"
	"github.com/bifrost0x/webssh/internal/store/storetest"
	"github.com/bifrost0x/webssh/internal/vault"
)

type automationOracle struct {
	Golden map[string][]struct {
		UserID int64  `json:"user_id"`
		RunID  string `json:"run_id"`
		JSON   string `json:"json"`
		CSV    string `json:"csv"`
	} `json:"golden"`
}

func readAutomationOracle(t *testing.T) automationOracle {
	t.Helper()
	raw, err := os.ReadFile("../../automation/testdata/oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var o automationOracle
	if err := json.Unmarshal(raw, &o); err != nil {
		t.Fatal(err)
	}
	return o
}

func automationOptions(t *testing.T, dir, secret string, wrap func(Step) Step) Options {
	t.Helper()
	o := testOptions(t, dir)
	r := credentialsRegistry(t)
	if wrap == nil {
		if err := AddAutomation(r); err != nil {
			t.Fatal(err)
		}
	} else {
		r.Schemas(automation.Schema())
		for _, s := range []func() Step{func() Step { return &runbooksStep{} }, func() Step { return &runsStep{} }} {
			if err := r.Add(GroupAutomation, func() Step { return wrap(s()) }); err != nil {
				t.Fatal(err)
			}
		}
	}
	o.Registry = r
	o.Secret = secret
	return o
}

func migrateAutomation(t *testing.T, dir, secret string) migrated {
	t.Helper()
	before := legacySnapshot(t, dir)
	st, err := startClosed(automationOptions(t, dir, secret, nil))
	if err != nil || !st.Migrated {
		t.Fatalf("migration: %+v, %v", st, err)
	}
	assertUntouched(t, dir, before)
	return openMigrated(t, dir, secret, st.Report)
}

// checkExports compares the migrated runbooks' digests and the exports
// of the migrated runs with the Python release on the same archive.
func checkExports(t *testing.T, m migrated, archive string) {
	t.Helper()
	o := readAutomationOracle(t)
	books, runs := o.Golden[archive+":runbooks"], o.Golden[archive]
	if len(books) == 0 || len(runs) == 0 {
		t.Fatalf("the oracle has no automation data for %s", archive)
	}
	err := m.db.Read(t.Context(), func(tx *store.Tx) error {
		for _, want := range books {
			got, err := automation.ReadRunbooksTx(t.Context(), tx, want.UserID)
			if err != nil {
				return err
			}
			i := slices.IndexFunc(got, func(b automation.Runbook) bool { return b.ID == want.RunID })
			if i < 0 || got[i].Digest() != want.JSON {
				t.Errorf("runbook %s: digest differs from Python", want.RunID)
			}
		}
		for _, want := range runs {
			got, err := automation.ExportRunsTx(t.Context(), tx, want.UserID)
			if err != nil {
				return err
			}
			i := slices.IndexFunc(got, func(r automation.Run) bool { return r.ID == want.RunID })
			if i < 0 {
				t.Fatalf("run %s missing", want.RunID)
			}
			wj, _ := base64.StdEncoding.DecodeString(want.JSON)
			wc, _ := base64.StdEncoding.DecodeString(want.CSV)
			if !bytes.Equal(automation.ExportJSON(got[i]), wj) {
				t.Errorf("JSON export of %s:\n got %s\nwant %s", want.RunID, automation.ExportJSON(got[i]), wj)
			}
			if !bytes.Equal(automation.ExportCSV(got[i]), wc) {
				t.Errorf("CSV export of %s:\n got %q\nwant %q", want.RunID, automation.ExportCSV(got[i]), wc)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// E29 and E31 functionally: the runbooks keep their digests, the run
// keeps its export, and the migrated runbook reviews against the
// migrated saved host, its saved password and its trusted host key.
func TestAutomationMigrateGolden(t *testing.T) {
	t.Parallel()
	dir := copyGolden(t)
	m := migrateAutomation(t, dir, golden.manifest.SecretKey.Value)
	for _, p := range m.report.Pending {
		if p.Entity == "E29" || p.Entity == "E31" {
			t.Errorf("%s still pending", p.Entity)
		}
	}
	if e := m.entity(t, "E29"); e.Read != 2 || e.Written != 2 || len(e.Flagged) != 0 {
		t.Errorf("E29 report %+v", e)
	}
	if e := m.entity(t, "E31"); e.Read != 1 || e.Written != 1 {
		t.Errorf("E31 report %+v", e)
	}
	checkExports(t, m, "datadir.tar")

	owner := goldenUserByName(t, "local_user").ID
	svc := migratedAutomation(t, m)
	var books []automation.Runbook
	_ = m.db.Read(t.Context(), func(tx *store.Tx) error {
		var err error
		books, err = automation.ReadRunbooksTx(t.Context(), tx, owner)
		return err
	})
	if len(books) != 2 || len(books[1].Steps) != 20 || books[1].Steps[19].Timeout != 300 || !books[0].Steps[1].Sudo {
		t.Fatalf("runbooks after the migration: %+v", books)
	}
	rid := golden.manifest.Values.NamedCredential.ResourceID
	body, _ := json.Marshal(map[string]any{"runbook_id": books[0].ID, "profile_ids": []string{rid}})
	out, err := svc.Preview(t.Context(), owner, "session", jsontext.Value(body))
	if err != nil {
		t.Fatalf("review of the migrated runbook: %v", err)
	}
	var review struct {
		Confirmation string `json:"confirmation"`
		Targets      []struct {
			Host string `json:"host"`
		} `json:"targets"`
	}
	if err := json.Unmarshal(out, &review); err != nil || review.Confirmation != "1" || review.Targets[0].Host != "pw.golden.test" {
		t.Fatalf("review %s: %v", out, err)
	}
	runs, err := svc.History(t.Context(), owner)
	if err != nil || len(runs) != 1 || runs[0].Status != "failed" {
		t.Fatalf("history: %v %v", runs, err)
	}
}

// The extended 3.3.x data set migrates the same way.
func TestAutomationMigrateExtended(t *testing.T) {
	t.Parallel()
	fx := legacyFixture(t)
	dir := extractLegacy(t, "datadir-extended.tar")
	m := migrateAutomation(t, dir, fx.SecretKey.Value)
	checkExports(t, m, "datadir-extended.tar")
}

// An unfinished run gets the load-time rule; a store Python cannot read
// stops the migration and leaves no Go database.
func TestAutomationMigrateInterruptedAndInvalid(t *testing.T) {
	t.Parallel()
	owner := goldenUserByName(t, "local_user").ID
	runsFile := func(dir string) string {
		return filepath.Join(dir, "users", "user_"+strconv.FormatInt(owner, 10), "automation-runs.json")
	}
	dir := copyGolden(t)
	raw, err := os.ReadFile(runsFile(dir))
	if err != nil {
		t.Fatal(err)
	}
	open := strings.Replace(strings.Replace(string(raw), `"status": "failed",
      "targets"`, `"status": "running",
      "targets"`, 1), `"status": "failed",
              "exit_code"`, `"status": "running",
              "exit_code"`, 1)
	if open == string(raw) {
		t.Fatal("fixture layout changed")
	}
	writeFile(t, runsFile(dir), open)
	m := migrateAutomation(t, dir, golden.manifest.SecretKey.Value)
	_ = m.db.Read(t.Context(), func(tx *store.Tx) error {
		runs, err := automation.ExportRunsTx(t.Context(), tx, owner)
		if err != nil || len(runs) != 1 || runs[0].Status != "unknown" || runs[0].Targets[0].Steps[0].Reason == nil ||
			runs[0].Targets[0].Steps[0].Status != "unknown" || *runs[0].Targets[0].Steps[0].Reason != "run_interrupted" {
			t.Errorf("interrupted run: %+v %v", runs, err)
		}
		return nil
	})
	if e := m.entity(t, "E31"); len(e.Notes) == 0 {
		t.Errorf("no note on the interrupted run: %+v", e)
	}

	for name, damage := range map[string]func(string) string{
		"automation-runs.json": func(s string) string { return strings.Replace(s, `"exit_code": 1`, `"exit_code": -1`, 1) },
		"automation.json":      func(s string) string { return strings.Replace(s, `"timeout": 5`, `"timeout": 5.0`, 1) },
	} {
		dir := copyGolden(t)
		path := filepath.Join(dir, "users", "user_"+strconv.FormatInt(owner, 10), name)
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if damaged := damage(string(raw)); damaged != string(raw) {
			writeFile(t, path, damaged)
		} else {
			t.Fatalf("%s: fixture layout changed", name)
		}
		before := legacySnapshot(t, dir)
		st, err := startClosed(automationOptions(t, dir, golden.manifest.SecretKey.Value, nil))
		if err == nil || (st != nil && st.Migrated) {
			t.Errorf("%s: an invalid store migrated", name)
		}
		assertUntouched(t, dir, before)
		assertNoGoDatabase(t, dir)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// Verify notices a stored runbook or run that differs from what was read.
func TestAutomationVerifyDetectsTampering(t *testing.T) {
	t.Parallel()
	o := readOracleRuns(t)
	for _, tamper := range []string{
		`UPDATE automation_runbook_steps SET command = 'rm -rf /'`,
		`UPDATE automation_runbooks SET stop_on_error = 1 - stop_on_error`,
		`DELETE FROM automation_runbook_steps WHERE position = 1`,
		`UPDATE automation_runs SET document = replace(document, 'boom', 'b00m')`,
		`DELETE FROM automation_runs`,
	} {
		db := storetest.Open(t, automation.Schema())
		books := &runbooksStep{users: []userRunbooks{{id: 1, books: []automation.Runbook{{ID: "b", Name: "B", StopOnError: true,
			Steps: []automation.Step{{Name: "a", Command: "id", Timeout: 5}, {Name: "b", Command: "df", Timeout: 9, Sudo: true}}}}}}}
		runs := &runsStep{users: []userRuns{{id: 1, runs: o}}}
		ctx := t.Context()
		write := func(fn func(tx *store.Tx) error) error { return db.Write(ctx, fn) }
		if err := write(func(tx *store.Tx) error {
			return errors.Join(books.Write(ctx, tx, nil), runs.Write(ctx, tx, nil))
		}); err != nil {
			t.Fatal(err)
		}
		verify := func() error {
			return db.Read(ctx, func(tx *store.Tx) error {
				return errors.Join(books.Verify(ctx, tx, nil), runs.Verify(ctx, tx, nil))
			})
		}
		if err := verify(); err != nil {
			t.Fatalf("untouched: %v", err)
		}
		if err := write(func(tx *store.Tx) error { _, err := tx.ExecContext(ctx, tamper); return err }); err != nil {
			t.Fatal(err)
		}
		if err := verify(); err == nil {
			t.Errorf("%s: not detected", tamper)
		}
	}
}

func readOracleRuns(t *testing.T) []automation.Run {
	t.Helper()
	raw, err := os.ReadFile("../../automation/testdata/oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var o struct {
		Runs []struct {
			Stored string `json:"stored"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(raw, &o); err != nil {
		t.Fatal(err)
	}
	r, err := automation.ParseRun(jsontext.Value(o.Runs[0].Stored))
	if err != nil {
		t.Fatal(err)
	}
	return []automation.Run{r}
}

// migratedAutomation is the automation over the migrated database, with
// the real vault, hosts and host keys; it never dials.
func migratedAutomation(t *testing.T, m migrated) *automation.Service {
	t.Helper()
	steps := &principaltest.StepUp{}
	v, err := vault.New(vault.Options{DB: m.db, Sealer: m.ring, StepUp: steps, Limits: vault.Limits{MaxRecords: 100, MaxStoreBytes: 8 << 20}})
	if err != nil {
		t.Fatal(err)
	}
	if err := v.EnableCredentials(vault.CredentialOptions{Stores: migratedStores{m.db}, Policy: enabledPolicy{},
		Accounts: migratedIncarnations{nil}}); err != nil {
		t.Fatal(err)
	}
	svc, err := automation.New(automation.Options{DB: m.db, Records: migratedStores{m.db}, Passwords: v,
		Keys: migratedKeys{v}, HostTrust: migratedTrust{hostkey.New(m.db, nil)}, Resolver: &hosts.Service{DB: m.db, Keys: v},
		Dialer: noDial{}, Switches: onSwitches{}, Quotas: noQuota{}, StepUp: steps})
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

type migratedKeys struct{ v *vault.Service }

func (k migratedKeys) PublicKey(ctx context.Context, owner int64, id string) ([]byte, error) {
	s, err := k.v.Signer(ctx, owner, id)
	if err != nil {
		return nil, err
	}
	return s.PublicKey().Marshal(), nil
}

type migratedTrust struct{ s *hostkey.Store }

func (m migratedTrust) Trusted(ctx context.Context, owner int64, host string, port int) (bool, error) {
	r, err := m.s.Effective(ctx, owner, []hostkey.Target{{Host: host, Port: port}})
	if err != nil {
		return false, err
	}
	return len(r) == 1 && slices.ContainsFunc(r[0].Keys, func(k hostkey.KeyReport) bool { return k.Status == "effective" }), nil
}

type noDial struct{}

func (noDial) Dial(context.Context, client.Target, client.Interaction) (automation.Conn, error) {
	return nil, errors.New("no network in this test")
}

type onSwitches struct{}

func (onSwitches) AutomationEnabled(context.Context) (bool, error)  { return true, nil }
func (onSwitches) CredentialsEnabled(context.Context) (bool, error) { return true, nil }

type noQuota struct{}

func (noQuota) Reserve(context.Context, string, int64, int64) (func(), error) { return func() {}, nil }
