package automation

import (
	"context"
	"encoding/json/jsontext"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/principal/principaltest"
	"github.com/bifrost0x/webssh/internal/pyjson"
)

func wantCode(t *testing.T, err error, code fault.Code) {
	t.Helper()
	if fault.CodeOf(err) != code {
		t.Fatalf("error %v (%s), want %s", err, fault.CodeOf(err), code)
	}
}

func (e *scheduleEnv) one(t *testing.T, id string) jsontext.Value {
	t.Helper()
	items, err := e.s.List(t.Context(), 7)
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range items {
		if jsonMember(it, "id") == id {
			return it
		}
	}
	t.Fatalf("schedule %s not listed", id)
	return nil
}

func boolMember(v jsontext.Value, name string) bool {
	m, _ := pyjson.Get(v, name)
	return string(m) == "true"
}

func (e *scheduleEnv) tickAt(t *testing.T, at time.Time) {
	t.Helper()
	e.clock.set(at)
	if err := e.s.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
}

var nine = time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC)

func TestScheduleApproveAndList(t *testing.T) {
	t.Parallel()
	e := newScheduleEnv(t)
	pv, err := e.s.Prepare(t.Context(), e.p, jsontext.Value(`{"runbook_id":"b1","profile_ids":["p1","p2"],"cron":"0 9 * * *","timezone":"UTC"}`))
	if err != nil {
		t.Fatal(err)
	}
	runs, _ := pyjson.Get(pv, "next_runs")
	if string(runs) != `["2026-03-01T09:00:00+00:00","2026-03-02T09:00:00+00:00","2026-03-03T09:00:00+00:00"]` {
		t.Fatalf("next_runs %s", runs)
	}
	if jsonMember(pv, "confirmation") != "2" {
		t.Fatalf("preview %s", pv)
	}
	token := jsonMember(pv, "intent")
	// Wrong count, missing grant, another session: nothing is stored.
	_, err = e.s.Approve(t.Context(), e.p, token, "1", "")
	wantCode(t, err, fault.ConfirmationRequired)
	_, err = e.s.Approve(t.Context(), e.p, token, "2", "forged")
	wantCode(t, err, fault.StepUpRequired)
	other := e.p
	other.SessionID = "other-session"
	_, err = e.s.Approve(t.Context(), other, token, "2", "")
	wantCode(t, err, fault.InvalidIntent)

	e.stepUp.Issue(e.p, principal.ActionAutomationSchedule, token, "g")
	out, err := e.s.Approve(t.Context(), e.p, token, "2", "g")
	if err != nil {
		t.Fatal(err)
	}
	if jsonMember(out, "last_status") != StatusWaiting || jsonMember(out, "next_due") != "2026-03-01T09:00:00+00:00" ||
		jsonMember(out, "name") != "Nächtlich ✓" || jsonMember(out, "runbook_id") != "b1" || !boolMember(out, "enabled") {
		t.Fatalf("schedule %s", out)
	}
	if ids, _ := pyjson.Get(out, "profile_ids"); string(ids) != `["p1","p2"]` {
		t.Fatalf("profile_ids %s", ids)
	}
	// The intent is used up.
	e.stepUp.Issue(e.p, principal.ActionAutomationSchedule, token, "g2")
	_, err = e.s.Approve(t.Context(), e.p, token, "2", "g2")
	wantCode(t, err, fault.InvalidIntent)
	// Another account sees nothing and cannot pause it.
	items, _ := e.s.List(t.Context(), 8)
	if len(items) != 0 {
		t.Fatal("listed for another account")
	}
	_, err = e.s.Pause(t.Context(), 8, jsonMember(out, "id"))
	wantCode(t, err, fault.NotFound)
	if len(e.audit.events) != 1 || e.audit.events[0] != "AUTOMATION_SCHEDULE_APPROVED" {
		t.Fatalf("audit %v", e.audit.events)
	}
}

func TestSchedulePrepareRefusals(t *testing.T) {
	t.Parallel()
	e := newScheduleEnv(t)
	for _, body := range []string{
		`{"runbook_id":"b1","cron":"61 * * * *","timezone":"UTC"}`,
		`{"runbook_id":"b1","cron":"* * * * *","timezone":"Mars/Base"}`,
		`{"runbook_id":"b1","cron":5,"timezone":"UTC"}`,
		`{"runbook_id":"b1","timezone":"UTC"}`,
	} {
		_, err := e.s.Prepare(t.Context(), e.p, jsontext.Value(body))
		wantCode(t, err, fault.InvalidSchedule)
	}
	_, err := e.s.Prepare(t.Context(), e.p, jsontext.Value(`{"runbook_id":"b1","cron":"* * * * *","timezone":"UTC","schedule_id":"nope"}`))
	wantCode(t, err, fault.NotFound)
	// A password hop without an assigned password cannot be scheduled.
	e.passwords.set("p2", "")
	delete(e.passwords.versions, "p2")
	_, err = e.s.Prepare(t.Context(), e.p, jsontext.Value(`{"runbook_id":"b1","cron":"* * * * *","timezone":"UTC"}`))
	wantCode(t, err, fault.CredentialMissing)
	e.policy.set(false, "r1")
	_, err = e.s.Prepare(t.Context(), e.p, jsontext.Value(`{"runbook_id":"b1","cron":"* * * * *","timezone":"UTC"}`))
	wantCode(t, err, fault.AutomationDisabled)
}

func TestScheduleRunsOncePerSlotAndFinishes(t *testing.T) {
	t.Parallel()
	e := newScheduleEnv(t)
	id := e.approve(t, "0 9 * * *", "UTC")
	e.tickAt(t, nine.Add(-time.Second))
	if len(e.wf.runs()) != 0 {
		t.Fatal("ran before its slot")
	}
	e.tickAt(t, nine.Add(2*time.Second))
	e.tickAt(t, nine.Add(4*time.Second))
	runs := e.wf.runs()
	if len(runs) != 1 {
		t.Fatalf("%d runs, want one", len(runs))
	}
	run := runs[0]
	if run.UserID != 7 || run.ScheduleID != id || len(run.ClaimID) != 48 || !sameJSON(run.Snapshot.Book, e.wf.book) {
		t.Fatalf("run %+v", run)
	}
	got := e.one(t, id)
	if jsonMember(got, "last_status") != StatusRunning || !boolMember(got, "running") || jsonMember(got, "next_due") != "2026-03-02T09:00:00+00:00" {
		t.Fatalf("after dispatch %s", got)
	}
	if err := run.Check(t.Context()); err != nil {
		t.Fatalf("check of the running run: %v", err)
	}
	if pw, err := run.Password(t.Context(), e.wf.targets[1]); err != nil || string(pw) != "secret" {
		t.Fatalf("password %q %v", pw, err)
	}
	run.Finish(t.Context(), "succeeded")
	got = e.one(t, id)
	if jsonMember(got, "last_status") != "succeeded" || boolMember(got, "running") {
		t.Fatalf("after finish %s", got)
	}
	// The finished claim cannot be checked again.
	wantCode(t, run.Check(t.Context()), fault.PreviewChanged)
	e.tickAt(t, nine.Add(24*time.Hour+time.Second))
	if len(e.wf.runs()) != 2 {
		t.Fatal("the next slot did not run")
	}
}

// A run without a signed-in session is a trust boundary: it happens only
// with a valid approval and a valid account.
func TestScheduleDoesNotRunWithoutValidApprovalOrAccount(t *testing.T) {
	t.Parallel()
	cases := map[string]func(e *scheduleEnv){
		"locked account":   func(e *scheduleEnv) { e.accounts.update(7, func(b *AccountBinding) { b.Locked = true }) },
		"deleted account":  func(e *scheduleEnv) { e.accounts.remove(7) },
		"password changed": func(e *scheduleEnv) { e.accounts.update(7, func(b *AccountBinding) { b.AuthGeneration++ }) },
		"global sign-out":  func(e *scheduleEnv) { e.accounts.update(7, func(b *AccountBinding) { b.Epoch = "e2" }) },
		"new account same id": func(e *scheduleEnv) {
			e.accounts.update(7, func(b *AccountBinding) { b.Incarnation = "2026-02-02T00:00:00" })
		},
		"policy revision":       func(e *scheduleEnv) { e.policy.set(true, "r2") },
		"target changed":        func(e *scheduleEnv) { e.wf.changeTarget(0, `{"id":"p1","host":"elsewhere.example"}`) },
		"password replaced":     func(e *scheduleEnv) { e.passwords.set("p2", "v2") },
		"password unassigned":   func(e *scheduleEnv) { delete(e.passwords.versions, "p2") },
		"key replaced":          func(e *scheduleEnv) { e.wf.keys = map[string]string{"p1": "other"} },
		"automation turned off": func(e *scheduleEnv) { e.policy.set(false, "r1") },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := newScheduleEnv(t)
			e.approve(t, "0 9 * * *", "UTC")
			change(e)
			e.tickAt(t, nine.Add(time.Second))
			if len(e.wf.runs()) != 0 {
				t.Fatal("ran without a valid approval")
			}
		})
	}
}

func TestScheduleFailedApprovalNeedsReview(t *testing.T) {
	t.Parallel()
	e := newScheduleEnv(t)
	id := e.approve(t, "0 9 * * *", "UTC")
	e.passwords.set("p2", "v2")
	e.tickAt(t, nine.Add(time.Second))
	got := e.one(t, id)
	if jsonMember(got, "last_status") != StatusNeedsReview || boolMember(got, "enabled") {
		t.Fatalf("%s", got)
	}
	// Restoring the old state does not resume it; only a new approval does.
	e.passwords.set("p2", "v1")
	e.tickAt(t, nine.Add(24*time.Hour+time.Second))
	if len(e.wf.runs()) != 0 {
		t.Fatal("a schedule that needs review ran")
	}
}

func TestScheduleChangeDuringRunStopsIt(t *testing.T) {
	t.Parallel()
	for name, change := range map[string]func(e *scheduleEnv, id string){
		"pause":  func(e *scheduleEnv, id string) { _, _ = e.s.Pause(context.Background(), 7, id) },
		"delete": func(e *scheduleEnv, id string) { _ = e.s.Delete(context.Background(), 7, id) },
		"lock":   func(e *scheduleEnv, _ string) { e.accounts.update(7, func(b *AccountBinding) { b.Locked = true }) },
		"cancel": func(e *scheduleEnv, id string) {
			r := e.wf.runs()[0]
			_, _ = e.s.CancelRun(context.Background(), 7, id, r.ClaimID)
		},
		"keys":    func(e *scheduleEnv, _ string) { e.wf.keys = map[string]string{"p1": "x"} },
		"version": func(e *scheduleEnv, _ string) { e.passwords.set("p2", "v9") },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := newScheduleEnv(t)
			id := e.approve(t, "0 9 * * *", "UTC")
			e.tickAt(t, nine.Add(time.Second))
			run := e.wf.runs()[0]
			change(e, id)
			if err := run.Check(t.Context()); err == nil {
				t.Fatal("the run still passes its check")
			}
			if _, err := run.Password(t.Context(), e.wf.targets[1]); err == nil {
				t.Fatal("the run still gets its password")
			}
		})
	}
}

func TestSchedulePausedAndLateSlots(t *testing.T) {
	t.Parallel()
	e := newScheduleEnv(t)
	id := e.approve(t, "0 9 * * *", "UTC")
	out, err := e.s.Pause(t.Context(), 7, id)
	if err != nil || jsonMember(out, "last_status") != StatusPaused || boolMember(out, "enabled") {
		t.Fatalf("pause %s %v", out, err)
	}
	e.tickAt(t, nine.Add(time.Second))
	if len(e.wf.runs()) != 0 {
		t.Fatal("a paused schedule ran")
	}
	e2 := newScheduleEnv(t)
	id2 := e2.approve(t, "0 9 * * *", "UTC")
	e2.tickAt(t, nine.Add(61*time.Second))
	if len(e2.wf.runs()) != 0 || jsonMember(e2.one(t, id2), "last_status") != StatusMissed {
		t.Fatal("a late slot was not recorded as missed")
	}
}

func TestScheduleDispatchFailures(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		err     error
		status  string
		enabled bool
		running bool
	}{
		{&NotDispatchedError{Code: fault.Busy}, StatusSkipped, true, false},
		{&NotDispatchedError{Code: fault.Unavailable}, StatusSkipped, true, false},
		{&NotDispatchedError{Code: fault.PreviewChanged}, StatusNeedsReview, false, false},
		{errors.New("connection lost after dispatch"), StatusUnknown, false, true},
	} {
		e := newScheduleEnv(t)
		id := e.approve(t, "0 9 * * *", "UTC")
		e.wf.startErr = c.err
		e.tickAt(t, nine.Add(time.Second))
		got := e.one(t, id)
		if jsonMember(got, "last_status") != c.status || boolMember(got, "enabled") != c.enabled || boolMember(got, "running") != c.running {
			t.Errorf("%v: %s", c.err, got)
		}
	}
}

func TestScheduleStaleClaimIsRecoveredAsUnknown(t *testing.T) {
	t.Parallel()
	e := newScheduleEnv(t)
	e.clock.set(nine.Add(-time.Minute))
	id := e.approve(t, "*/5 * * * *", "UTC")
	e.tickAt(t, nine.Add(time.Second))
	if len(e.wf.runs()) != 1 {
		t.Fatal("no run")
	}
	// The run never finishes; the next slots overlap until the claim is
	// stale, then the schedule stops with an unknown outcome.
	e.tickAt(t, nine.Add(5*time.Minute+time.Second))
	if got := e.one(t, id); jsonMember(got, "last_status") != StatusOverlap {
		t.Fatalf("overlap %s", got)
	}
	if err := e.wf.runs()[0].Check(t.Context()); err != nil {
		t.Fatalf("an overlap fenced the running run: %v", err)
	}
	e.tickAt(t, nine.Add(32*time.Minute))
	got := e.one(t, id)
	if jsonMember(got, "last_status") != StatusUnknown || boolMember(got, "enabled") || boolMember(got, "running") {
		t.Fatalf("stale claim %s", got)
	}
	if len(e.wf.runs()) != 1 {
		t.Fatal("an ambiguous run was replayed")
	}
	// A new approval keeps the unknown status visible until the next run.
	pv, err := e.s.Prepare(t.Context(), e.p, jsontext.Value(`{"runbook_id":"b1","cron":"0 9 * * *","timezone":"UTC","schedule_id":"`+id+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	token := jsonMember(pv, "intent")
	e.stepUp.Issue(e.p, principal.ActionAutomationSchedule, token, "g")
	out, err := e.s.Approve(t.Context(), e.p, token, "2", "g")
	if err != nil || jsonMember(out, "last_status") != StatusUnknown || !boolMember(out, "enabled") || jsonMember(out, "id") != id {
		t.Fatalf("re-approval %s %v", out, err)
	}
}

func TestScheduleReplacementNeedsTheReviewedRevision(t *testing.T) {
	t.Parallel()
	e := newScheduleEnv(t)
	id := e.approve(t, "0 9 * * *", "UTC")
	pv, err := e.s.Prepare(t.Context(), e.p, jsontext.Value(`{"runbook_id":"b1","cron":"0 10 * * *","timezone":"UTC","schedule_id":"`+id+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.s.Pause(t.Context(), 7, id); err != nil {
		t.Fatal(err)
	}
	token := jsonMember(pv, "intent")
	e.stepUp.Issue(e.p, principal.ActionAutomationSchedule, token, "g")
	_, err = e.s.Approve(t.Context(), e.p, token, "2", "g")
	wantCode(t, err, fault.PreviewChanged)
}

func TestScheduleLimitAndDelete(t *testing.T) {
	t.Parallel()
	e := newScheduleEnv(t)
	var last string
	for range MaxSchedules {
		last = e.approve(t, "0 9 * * *", "UTC")
	}
	pv, err := e.s.Prepare(t.Context(), e.p, jsontext.Value(`{"runbook_id":"b1","cron":"0 9 * * *","timezone":"UTC"}`))
	if err != nil {
		t.Fatal(err)
	}
	token := jsonMember(pv, "intent")
	e.stepUp.Issue(e.p, principal.ActionAutomationSchedule, token, "g")
	_, err = e.s.Approve(t.Context(), e.p, token, "2", "g")
	wantCode(t, err, fault.StorageLimit)
	if err := e.s.Delete(t.Context(), 7, last); err != nil {
		t.Fatal(err)
	}
	wantCode(t, e.s.Delete(t.Context(), 7, last), fault.NotFound)
	wantCode(t, e.s.Delete(t.Context(), 7, strings.Repeat("x", 37)), fault.NotFound)
}

func TestSchedulePrepareRunValidatesTheSchedule(t *testing.T) {
	t.Parallel()
	e := newScheduleEnv(t)
	id := e.approve(t, "0 9 * * *", "UTC")
	if _, err := e.s.PrepareRun(t.Context(), e.p, id); err != nil {
		t.Fatal(err)
	}
	check := e.wf.manual[0]
	if err := check(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := e.s.Pause(t.Context(), 7, id); err != nil {
		t.Fatal(err)
	}
	wantCode(t, check(t.Context()), fault.PreviewChanged)
	_, err := e.s.PrepareRun(t.Context(), principaltest.User(8), id)
	wantCode(t, err, fault.NotFound)
}

func TestScheduleIntentsBoundsAndRevocation(t *testing.T) {
	t.Parallel()
	e := newScheduleEnv(t)
	var tokens []string
	for range intentsPerUser + 1 {
		pv, err := e.s.Prepare(t.Context(), e.p, jsontext.Value(`{"runbook_id":"b1","cron":"0 9 * * *","timezone":"UTC"}`))
		if err != nil {
			t.Fatal(err)
		}
		tokens = append(tokens, jsonMember(pv, "intent"))
		e.clock.set(e.clock.now().Add(time.Millisecond))
	}
	if _, err := e.s.intents.get(e.p, tokens[0], false); err == nil {
		t.Fatal("the oldest intent survived the per-user bound")
	}
	if _, err := e.s.intents.get(e.p, tokens[1], false); err != nil {
		t.Fatal(err)
	}
	e.s.Revoke(principal.Revocation{UserID: 7, SessionID: e.p.SessionID})
	if _, err := e.s.intents.get(e.p, tokens[1], false); err == nil {
		t.Fatal("an intent survived its session")
	}
	pv, _ := e.s.Prepare(t.Context(), e.p, jsontext.Value(`{"runbook_id":"b1","cron":"0 9 * * *","timezone":"UTC"}`))
	e.clock.set(e.clock.now().Add(IntentTTL))
	if _, err := e.s.intents.get(e.p, jsonMember(pv, "intent"), false); err == nil {
		t.Fatal("an expired intent was accepted")
	}
}
