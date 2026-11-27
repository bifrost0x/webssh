package legacy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"maps"
	"strings"

	"github.com/bifrost0x/webssh/internal/automation"
	"github.com/bifrost0x/webssh/internal/cron"
	"github.com/bifrost0x/webssh/internal/pyjson"
	"github.com/bifrost0x/webssh/internal/session"
	"github.com/bifrost0x/webssh/internal/store"
)

// AddSchedules registers the step of the area "schedules": the automation
// schedules (E15). It takes over the entity the M1 release keeps in place.
func AddSchedules(r *Registry) error {
	// The approvals bind to the sign-out generation of the new database.
	r.Schemas(session.Schema(), automation.ScheduleSchema())
	return r.Add(GroupAutomation, func() Step { return &schedulesStep{} })
}

// schedulesStep migrates entity E15 (migration specification 3.2 and
// 4.3). Each grant is first validated with the rules of the Python release
// against the legacy state (_validate_snapshot): the account tuple with the
// legacy session epoch, the automation policy revision, the runbook, the
// fingerprints of the targets, the key digests and the saved-password
// generations. A valid grant becomes an approval bound to the same values
// and to the sign-out generation of the new database, so an active
// schedule keeps running without a new approval; an invalid one is
// written stale and needs a review, as it would in Python. A row with a
// claim gets Python's recovery (paused, unknown, revision + 1): the
// Python release is stopped, so no run can still hold it. Schedules of an
// earlier account with the same id stay in place.
type schedulesStep struct {
	rows  []automation.ImportedSchedule
	kept  []KeptPath
	flags []Flag
	read  int
	epoch string
}

func (*schedulesStep) Entity() string { return "E15" }

func (*schedulesStep) Version() int { return 1 }

// legacyGrant is the grant column of automation_schedules.
type legacyGrant struct {
	Book       jsontext.Value    `json:"book"`
	Targets    []jsontext.Value  `json:"targets"`
	KeyDigests map[string]string `json:"key_digests"`
	Binding    jsontext.Value    `json:"vault_generation"`
	Account    []jsontext.Value  `json:"account"`
	Policy     string            `json:"policy"`
}

func (s *schedulesStep) Read(ctx context.Context, src *Source) error {
	rows, err := src.Schedules(ctx)
	if err != nil || len(rows) == 0 {
		return err
	}
	s.read = len(rows)
	if data, err := src.readFile("session_epoch"); err == nil && validEpoch(data) {
		s.epoch = strings.Trim(string(data), pythonWhitespace)
	} else if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	st, err := newLegacyState(ctx, src)
	if err != nil {
		return err
	}
	for _, row := range rows {
		var g legacyGrant
		raw, _, err := pyjson.Load([]byte(row.Grant))
		if err == nil {
			err = json.Unmarshal(raw, &g)
		}
		if err != nil || g.Book.Kind() != '{' || len(g.Account) != 3 {
			return &StepError{UserID: row.UserID, Record: "automation_schedules:" + row.ID, Err: errors.New("legacy: the schedule grant cannot be read")}
		}
		if _, perr := cron.Parse(row.Cron); perr != nil || !validZone(row.Timezone) {
			return &StepError{UserID: row.UserID, Record: "automation_schedules:" + row.ID, Err: errors.New("legacy: the schedule's cron expression or time zone cannot be read")}
		}
		incarnation, _ := textOf(g.Account[0])
		u, ok := st.users[row.UserID]
		if !ok || !u.noIncarnation && u.incarnation != incarnation {
			s.kept = append(s.kept, KeptPath{Path: "webssh.db:automation_schedules/" + row.ID, Reason: "schedule_of_deleted_account"})
			continue
		}
		valid, reason := st.validGrant(ctx, src, row.UserID, s.epoch, g)
		in := automation.ImportedSchedule{ID: row.ID, UserID: row.UserID, Revision: row.Revision, Enabled: row.Enabled,
			Cron: row.Cron, Zone: row.Timezone, NextAt: row.NextAt, LastStatus: row.LastStatus, Book: g.Book,
			Targets: g.Targets, KeyDigests: g.KeyDigests, Binding: g.Binding, Policy: g.Policy, Stale: !valid,
			Account: automation.AccountBinding{Incarnation: incarnation, AuthGeneration: u.authGeneration}}
		if in.KeyDigests == nil {
			in.KeyDigests = map[string]string{}
		}
		if row.ClaimID.Valid {
			in.Enabled, in.LastStatus, in.Revision = false, automation.StatusUnknown, row.Revision+1
			s.flags = append(s.flags, Flag{UserID: row.UserID, ID: row.ID, Reason: "interrupted_run_outcome_unknown"})
		}
		if !valid {
			s.flags = append(s.flags, Flag{UserID: row.UserID, ID: row.ID, Reason: "approval_needs_review: " + reason})
		}
		s.rows = append(s.rows, in)
	}
	return nil
}

func (s *schedulesStep) Write(ctx context.Context, tx *store.Tx, _ Sealer) error {
	if len(s.rows) == 0 {
		return nil
	}
	epoch, err := session.EpochTx(ctx, tx)
	if err != nil {
		return err
	}
	for i := range s.rows {
		s.rows[i].Account.Epoch = epoch
		if err := automation.ImportScheduleTx(ctx, tx, s.rows[i]); err != nil {
			return &StepError{UserID: s.rows[i].UserID, Record: s.rows[i].ID, Err: err}
		}
	}
	return nil
}

func (s *schedulesStep) Verify(ctx context.Context, tx *store.Tx, _ Opener) error {
	stored, err := automation.SchedulesTx(ctx, tx)
	if err != nil {
		return err
	}
	byID := map[string]automation.StoredSchedule{}
	for _, r := range stored {
		byID[r.ID] = r
	}
	for _, want := range s.rows {
		got, ok := byID[want.ID]
		if !ok || got.UserID != want.UserID || got.Revision != want.Revision || got.Enabled != want.Enabled ||
			got.Cron != want.Cron || got.Zone != want.Zone || got.NextAt != want.NextAt || got.LastStatus != want.LastStatus ||
			got.Policy != want.Policy || got.Stale != want.Stale || got.Claimed || !maps.Equal(got.KeyDigests, want.KeyDigests) ||
			!automation.SameJSON(got.Book, want.Book) || !automation.SameJSON(arrayOf(got.Targets), arrayOf(want.Targets)) ||
			!automation.SameJSON(got.Binding, nullIfEmpty(want.Binding)) ||
			!automation.SameJSON(got.AccountTuple, automation.AccountTuple(want.Account)) {
			return &StepError{UserID: want.UserID, Record: want.ID, Err: errors.New("legacy: the stored schedule differs from the legacy row")}
		}
	}
	if len(stored) != len(s.rows) {
		return fmt.Errorf("legacy: %d schedules stored, %d migrated", len(stored), len(s.rows))
	}
	return nil
}

func (s *schedulesStep) Report() StepReport {
	r := StepReport{Entity: "E15", Version: 1, Read: s.read, Written: len(s.rows), Flagged: s.flags, KeptInPlace: s.kept}
	if len(s.rows) > 0 {
		r.Notes = []string{"approved schedules keep their approval; a global sign-out, a password change or a changed target, key or saved password ends it, as before"}
	}
	return r
}

func arrayOf(items []jsontext.Value) jsontext.Value { return pyjson.Array(items) }

func nullIfEmpty(v jsontext.Value) jsontext.Value {
	if len(v) == 0 {
		return jsontext.Value("null")
	}
	return v
}

func textOf(v jsontext.Value) (string, bool) {
	if v.Kind() != '"' {
		return "", false
	}
	var s string
	return s, json.Unmarshal(v, &s) == nil
}

func validZone(name string) bool {
	_, err := cron.LoadZone(name)
	return err == nil
}

// keyDigest is _key_digest of app/automation_service.py: SHA-256 of the
// decrypted key text.
func keyDigest(pem []byte) string {
	sum := sha256.Sum256(pem)
	return hex.EncodeToString(sum[:])
}
