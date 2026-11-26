package legacy

import (
	"context"
	"encoding/json/jsontext"
	"time"

	"github.com/bifrost0x/webssh/internal/pyjson"
	"github.com/bifrost0x/webssh/internal/settings"
	"github.com/bifrost0x/webssh/internal/store"
)

// recoveryCheckStep migrates entity A07, DATA_DIR/recovery-check.json,
// the notice after a portable restore, into the application setting
// recovery_check. A malformed or oversized file reads as no notice, as
// in Python, and is FLAGged.
type recoveryCheckStep struct {
	check RecoveryCheck
	value jsontext.Value
	now   time.Time
}

func (*recoveryCheckStep) Entity() string { return "A07" }

func (*recoveryCheckStep) Version() int { return 1 }

func (s *recoveryCheckStep) Read(_ context.Context, src *Source) error {
	var err error
	if s.check, err = src.RecoveryCheck(); err != nil {
		return err
	}
	s.now = time.Now().UTC()
	if s.check.RestoredAt != "" {
		s.value = pyjson.Object([]pyjson.Member{{Name: "restored_at", Value: pyjson.String(s.check.RestoredAt)}})
	}
	return nil
}

func (s *recoveryCheckStep) Write(ctx context.Context, tx *store.Tx, _ Sealer) error {
	if s.value == nil {
		return nil
	}
	if err := settings.ImportRecoveryCheck(ctx, tx, s.value, s.now.UnixMicro()); err != nil {
		return &StepError{Record: "recovery-check.json", Err: err}
	}
	return nil
}

func (s *recoveryCheckStep) Verify(ctx context.Context, tx *store.Tx, _ Opener) error {
	if s.value == nil {
		return nil
	}
	if err := settings.VerifyRecoveryCheck(ctx, tx, s.value); err != nil {
		return &StepError{Record: "recovery-check.json", Err: err}
	}
	return nil
}

func (s *recoveryCheckStep) Report() StepReport {
	r := StepReport{Entity: "A07", Version: 1}
	if s.check.Present {
		r.Read = 1
	}
	if s.value != nil {
		r.Written = 1
		r.Notes = append(r.Notes, "the notice is stored; showing it follows in a later build")
	}
	if s.check.Malformed {
		r.Flagged = append(r.Flagged, Flag{ID: "recovery-check.json", Reason: "malformed: treated as no notice, as in the Python release"})
	}
	return r
}
