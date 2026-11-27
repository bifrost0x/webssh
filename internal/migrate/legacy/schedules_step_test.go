package legacy

import (
	"context"
	"encoding/json/jsontext"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/accounts"
	"github.com/bifrost0x/webssh/internal/automation"
	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/principal/principaltest"
	"github.com/bifrost0x/webssh/internal/pyjson"
	"github.com/bifrost0x/webssh/internal/session"
	"github.com/bifrost0x/webssh/internal/settings"
	"github.com/bifrost0x/webssh/internal/store"
	"github.com/bifrost0x/webssh/internal/store/storetest"
	"github.com/bifrost0x/webssh/internal/vault"
)

// scheduleAccountsOf is the account binding of cmd/webssh over the migrated
// database.
type scheduleAccountsOf struct{ db *store.DB }

func (m scheduleAccountsOf) ScheduleAccount(ctx context.Context, id int64) (automation.AccountBinding, error) {
	a, err := (&accounts.Service{DB: m.db}).Get(ctx, id)
	if err != nil {
		return automation.AccountBinding{}, err
	}
	var epoch string
	err = m.db.Read(ctx, func(tx *store.Tx) error {
		var err error
		epoch, err = session.EpochTx(ctx, tx)
		return err
	})
	return automation.AccountBinding{Incarnation: a.Incarnation, AuthGeneration: a.AuthGeneration, Epoch: epoch, Locked: a.IsLocked}, err
}

type migratedPolicy struct{ s *settings.Service }

func (p migratedPolicy) AutomationPolicy(ctx context.Context) (bool, string, error) {
	app, err := p.s.App(ctx)
	return true, app.AutomationRevision, err
}

// migratedWorkflows checks the frozen targets against the migrated saved
// hosts, as the run side does, and records the dispatched runs.
type migratedWorkflows struct {
	stores migratedStores
	mu     sync.Mutex
	runs   []automation.ScheduledRun
}

func (w *migratedWorkflows) Review(context.Context, principal.Principal, jsontext.Value) (automation.Snapshot, error) {
	return automation.Snapshot{}, fault.New(fault.Unavailable, "")
}

func (w *migratedWorkflows) Current(ctx context.Context, userID int64, s automation.Snapshot) error {
	r, err := w.stores.Records(ctx, userID)
	if err != nil {
		return err
	}
	current := map[string]string{}
	for _, res := range vault.ResourcesFromRecords(r) {
		if fp, ok := vault.RecordFingerprint(pyjsonObject(res)); ok {
			current[res.ID] = fp
		}
	}
	for _, t := range s.Targets {
		fp, _ := vault.RecordFingerprint(t)
		if current[memberText(t, "id")] != fp {
			return fault.New(fault.PreviewChanged, "")
		}
	}
	return nil
}

func (w *migratedWorkflows) PrepareManual(context.Context, principal.Principal, automation.Snapshot, func(context.Context) error) (jsontext.Value, error) {
	return nil, fault.New(fault.Unavailable, "")
}

func (w *migratedWorkflows) StartScheduled(_ context.Context, run automation.ScheduledRun) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.runs = append(w.runs, run)
	return nil
}

func schedulesRegistry(t *testing.T) *Registry {
	t.Helper()
	r := credentialsRegistry(t)
	if err := AddSchedules(r); err != nil {
		t.Fatal(err)
	}
	return r
}

// approvalEpoch is the session epoch of the golden data set when its
// schedules were approved. The generator rotates the epoch afterwards (a
// global sign-out for the cookie cases), so in the fixture as it is both
// grants are invalid; the Python release answers preview_changed for
// both (checked with _validate_snapshot on the fixture).
const approvalEpoch = "883b033c75b01839e333c978c2e9a9a4568c5f70a7f8af9757ece6891be57461"

// The global sign-out after the approval ends both approvals, as in
// Python: they are migrated stale and nothing runs.
func TestSchedulesMigrateGoldenAfterGlobalSignOut(t *testing.T) {
	t.Parallel()
	dir := copyGolden(t)
	m, rows := migrateSchedules(t, dir)
	stored := storedSchedules(t, m)
	for _, s := range stored {
		if !s.Stale {
			t.Errorf("schedule %s survived the global sign-out", s.ID)
		}
	}
	if len(stored) != len(rows) {
		t.Fatalf("%d of %d schedules migrated", len(stored), len(rows))
	}
	e := m.entity(t, "E15")
	if len(e.Flagged) != len(rows) || slices.ContainsFunc(e.Flagged, func(f Flag) bool { return !strings.HasSuffix(f.Reason, ": account_changed") }) {
		t.Fatalf("flags %+v", e.Flagged)
	}
	sched, wf := migratedSchedules(t, m, time.Unix(int64(stored[0].NextAt)+1, 0).Add(365*24*time.Hour))
	if err := sched.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(wf.runs) != 0 {
		t.Fatal("a stale approval ran")
	}
}

// E15 functionally: with the approval-time epoch (the grants are valid in
// Python, checked with _validate_snapshot), the active schedule runs at
// its next slot after the migration without a new approval and with its
// saved password, the paused one does not, and both keep their fields.
func TestSchedulesMigrateGolden(t *testing.T) {
	t.Parallel()
	dir := copyGolden(t)
	if err := os.WriteFile(filepath.Join(dir, "session_epoch"), []byte(approvalEpoch+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m, legacyRows := migrateSchedules(t, dir)
	stored := storedSchedules(t, m)
	for _, lr := range legacyRows {
		i := slices.IndexFunc(stored, func(s automation.StoredSchedule) bool { return s.ID == lr.ID })
		if i < 0 {
			t.Fatalf("schedule %s missing", lr.ID)
		}
		s := stored[i]
		if s.Cron != lr.Cron || s.Zone != lr.Timezone || s.NextAt != lr.NextAt || s.Enabled != lr.Enabled ||
			s.Revision != lr.Revision || s.LastStatus != lr.LastStatus || s.Stale {
			t.Errorf("schedule %s: %+v", lr.ID, s)
		}
	}
	active := golden.manifest.Values.Automation["schedule_id"].(string)
	paused := golden.manifest.Values.EdgeCases.Automation["paused_schedule"].(string)
	at := func(id string) time.Time {
		i := slices.IndexFunc(stored, func(s automation.StoredSchedule) bool { return s.ID == id })
		return time.Unix(int64(stored[i].NextAt), 0)
	}
	now := at(active).Add(time.Second)
	if p := at(paused).Add(time.Second); p.After(now) {
		now = p
	}
	sched, wf := migratedSchedules(t, m, now)
	if err := sched.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(wf.runs) != 1 || wf.runs[0].ScheduleID != active {
		t.Fatalf("runs after the migration: %+v", wf.runs)
	}
	run := wf.runs[0]
	if err := run.Check(t.Context()); err != nil {
		t.Fatalf("the migrated approval does not hold: %v", err)
	}
	hops := 0
	for _, hop := range run.Snapshot.Targets {
		if memberText(hop, "auth_type") != "password" {
			continue
		}
		hops++
		pw, err := run.Password(t.Context(), hop)
		if err != nil || string(pw) != golden.manifest.Values.NamedCredential.Password {
			t.Fatalf("saved password of the migrated schedule: %v", err)
		}
	}
	if hops == 0 {
		t.Fatal("the fixture schedule has no password hop")
	}
	// A changed saved password, a changed target and a global sign-out
	// each end the approval.
	change := func(query string, args ...any) {
		t.Helper()
		err := m.db.Write(t.Context(), func(tx *store.Tx) error {
			res, err := tx.ExecContext(t.Context(), query, args...)
			if err == nil {
				if n, _ := res.RowsAffected(); n != 1 {
					t.Fatalf("%s changed %d rows", query, n)
				}
			}
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	hop := run.Snapshot.Targets[0]
	change(`UPDATE vault_credentials SET version = version || 'x' WHERE id = (SELECT credential_id FROM vault_credential_assignments WHERE resource_id = ?)`, memberText(hop, "id"))
	if err := run.Check(t.Context()); err == nil {
		t.Fatal("the approval holds after the saved password changed")
	}
	change(`UPDATE vault_credentials SET version = substr(version, 1, length(version) - 1) WHERE id = (SELECT credential_id FROM vault_credential_assignments WHERE resource_id = ?)`, memberText(hop, "id"))
	if err := run.Check(t.Context()); err != nil {
		t.Fatalf("restoring the version: %v", err)
	}
	change(`UPDATE hosts_profiles SET host = ? WHERE id = ?`, pyjson.Quote("elsewhere.golden.test"), pyjson.Quote(memberText(hop, "id")))
	if err := run.Check(t.Context()); fault.CodeOf(err) != fault.PreviewChanged {
		t.Fatalf("after the target changed: %v", err)
	}
	change(`UPDATE hosts_profiles SET host = ? WHERE id = ?`, pyjson.Quote(memberText(hop, "host")), pyjson.Quote(memberText(hop, "id")))
	if err := run.Check(t.Context()); err != nil {
		t.Fatalf("restoring the target: %v", err)
	}
	// A global sign-out ends the approval, as rotating session_epoch did.
	err := m.db.Write(t.Context(), func(tx *store.Tx) error {
		_, err := tx.ExecContext(t.Context(), `UPDATE session_epoch SET value = 'rotated' WHERE singleton = 1`)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := run.Check(t.Context()); fault.CodeOf(err) != fault.PreviewChanged {
		t.Fatalf("after a global sign-out: %v", err)
	}
}

func migrateSchedules(t *testing.T, dir string) (migrated, []Schedule) {
	t.Helper()
	before := legacySnapshot(t, dir)
	o := testOptions(t, dir)
	o.Registry = schedulesRegistry(t)
	o.Secret = golden.manifest.SecretKey.Value
	st, err := startClosed(o)
	if err != nil || !st.Migrated {
		t.Fatalf("migration: %+v, %v", st, err)
	}
	assertUntouched(t, dir, before)
	m := openMigrated(t, dir, o.Secret, st.Report)
	for _, p := range m.report.Pending {
		if p.Entity == "E15" {
			t.Fatal("E15 is still pending")
		}
	}
	rows, err := golden.source.Schedules(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if e := m.entity(t, "E15"); e.Read != len(rows) || e.Written != len(rows) || len(rows) < 2 {
		t.Fatalf("E15 report %+v", e)
	}
	return m, rows
}

func storedSchedules(t *testing.T, m migrated) []automation.StoredSchedule {
	t.Helper()
	var stored []automation.StoredSchedule
	err := m.db.Read(t.Context(), func(tx *store.Tx) error {
		var err error
		stored, err = automation.SchedulesTx(t.Context(), tx)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return stored
}

func migratedSchedules(t *testing.T, m migrated, now time.Time) (*automation.Schedules, *migratedWorkflows) {
	t.Helper()
	_, svc, _ := migrateCredentialsOn(t, m)
	wf := &migratedWorkflows{stores: migratedStores{m.db}}
	sched, err := automation.NewSchedules(automation.ScheduleOptions{DB: m.db, Workflows: wf, Accounts: scheduleAccountsOf{m.db},
		Policy: migratedPolicy{settings.New(m.db, settings.Environment{})}, Passwords: svc, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	return sched, wf
}

// migratedCredentialsPolicy is the migrated saved-password switch.
type migratedCredentialsPolicy struct{ s *settings.Service }

func (p migratedCredentialsPolicy) CredentialsPolicy(ctx context.Context) (bool, string, error) {
	app, err := p.s.App(ctx)
	return app.CredentialsEnabled, app.CredentialsRevision, err
}

func pyjsonObject(r vault.Resource) jsontext.Value { return pyjson.Object(r.Page) }

// migrateCredentialsOn is the vault of migrateCredentials on m.
func migrateCredentialsOn(t *testing.T, m migrated) (migrated, *vault.Service, *principaltest.StepUp) {
	t.Helper()
	steps := &principaltest.StepUp{}
	svc, err := vault.New(vault.Options{DB: m.db, Sealer: m.ring, StepUp: steps, Limits: vault.Limits{MaxRecords: 100, MaxStoreBytes: 8 << 20}})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.EnableCredentials(vault.CredentialOptions{Stores: migratedStores{m.db}, Policy: migratedCredentialsPolicy{settings.New(m.db, settings.Environment{})},
		Accounts: migratedIncarnations{&accounts.Service{DB: m.db}}}); err != nil {
		t.Fatal(err)
	}
	return m, svc, steps
}

// The extended data set holds a schedule with a claim (the run of a
// stopped Python process) and one of an earlier account with the same
// id: the first is paused with an unknown outcome and never replayed, the
// second stays in place.
func TestSchedulesMigrateClaimAndDeletedAccount(t *testing.T) {
	t.Parallel()
	fx := legacyFixture(t)
	dir := extractLegacy(t, "datadir-extended.tar")
	before := legacySnapshot(t, dir)
	o := testOptions(t, dir)
	o.Registry = schedulesRegistry(t)
	o.Secret = fx.SecretKey.Value
	st, err := startClosed(o)
	if err != nil || !st.Migrated {
		t.Fatalf("migration: %+v, %v", st, err)
	}
	assertUntouched(t, dir, before)
	m := openMigrated(t, dir, o.Secret, st.Report)
	stale := fx.Values.Extended.Schedules["stale_claim"].ID
	foreign := fx.Values.Extended.Schedules["deleted_account"].ID
	stored := storedSchedules(t, m)
	i := slices.IndexFunc(stored, func(s automation.StoredSchedule) bool { return s.ID == stale })
	if i < 0 {
		t.Fatal("the claimed schedule is missing")
	}
	if s := stored[i]; s.Enabled || s.LastStatus != automation.StatusUnknown || s.Claimed || s.Revision != 2 {
		t.Fatalf("claimed schedule %+v", s)
	}
	if slices.ContainsFunc(stored, func(s automation.StoredSchedule) bool { return s.ID == foreign }) {
		t.Fatal("the schedule of a deleted account was migrated")
	}
	e := m.entity(t, "E15")
	if !slices.ContainsFunc(e.KeptInPlace, func(k KeptPath) bool { return strings.HasSuffix(k.Path, foreign) }) {
		t.Fatalf("kept in place %+v", e.KeptInPlace)
	}
}

// A grant or cron expression Python could not read stops the migration
// without changing the legacy data (STOP).
func TestSchedulesMigrateStopsOnUnreadableRows(t *testing.T) {
	t.Parallel()
	for name, stmt := range map[string]string{
		"grant": `UPDATE automation_schedules SET "grant" = '{"book": 1}'`,
		"cron":  `UPDATE automation_schedules SET cron = '61 * * * *'`,
		"zone":  `UPDATE automation_schedules SET timezone = 'Mars/Base'`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dir := copyGolden(t)
			execSQL(t, filepath.Join(dir, "app.db"), stmt)
			before := legacySnapshot(t, dir)
			o := testOptions(t, dir)
			o.Registry = schedulesRegistry(t)
			o.Secret = golden.manifest.SecretKey.Value
			if st, err := startClosed(o); err == nil && st.Migrated {
				t.Fatal("migrated an unreadable schedule")
			}
			assertUntouched(t, dir, before)
			assertNoGoDatabase(t, dir)
		})
	}
}

// Verify notices a stored schedule that differs from the legacy row.
func TestSchedulesVerifyDetectsTampering(t *testing.T) {
	t.Parallel()
	s := &schedulesStep{rows: []automation.ImportedSchedule{{ID: "s1", UserID: 3, Revision: 1, Enabled: true, Cron: "0 9 * * *",
		Zone: "UTC", NextAt: 1, LastStatus: "waiting", Book: jsontext.Value(`{"id":"b"}`), Targets: []jsontext.Value{jsontext.Value(`{"id":"p"}`)},
		KeyDigests: map[string]string{}, Account: automation.AccountBinding{Incarnation: "i", Epoch: "e"}, Policy: "r"}}}
	for _, tamper := range []string{
		`UPDATE automation_schedules SET enabled = 0`,
		`UPDATE automation_schedules SET next_at = 2`,
		`UPDATE automation_schedules SET approval = replace(approval, '"r"', '"x"')`,
		`DELETE FROM automation_schedules`,
	} {
		db := storetest.Open(t, automation.Schema())
		err := db.Write(t.Context(), func(tx *store.Tx) error {
			if err := automation.ImportScheduleTx(t.Context(), tx, s.rows[0]); err != nil {
				return err
			}
			if err := s.Verify(t.Context(), tx, nil); err != nil {
				t.Fatalf("untampered: %v", err)
			}
			if _, err := tx.ExecContext(t.Context(), tamper); err != nil {
				return err
			}
			if err := s.Verify(t.Context(), tx, nil); err == nil {
				t.Errorf("%s: not detected", tamper)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}
