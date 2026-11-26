package legacy

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/bifrost0x/webssh/internal/auth/totp"
	"github.com/bifrost0x/webssh/internal/otp"
	"github.com/bifrost0x/webssh/internal/store"
)

// totpStep migrates entity E08: every TOTP authenticator with its legacy
// id, its secret decrypted with the per-user Fernet key and sealed with
// the keyring, and its replay state (last_accepted_step). Unfinished
// enrolments are E09 and are not imported.
type totpStep struct {
	authenticators []totp.Imported
	keys           map[int64][]byte // decoded legacy secrets, for the code check
}

func (*totpStep) Entity() string { return "E08" }

func (*totpStep) Version() int { return 1 }

func (s *totpStep) Read(ctx context.Context, src *Source) error {
	secrets, err := src.TOTPAuthenticators(ctx)
	if err != nil {
		return err
	}
	times, err := totpTimes(ctx, src)
	if err != nil {
		return err
	}
	for _, t := range secrets {
		if t.Pending {
			continue
		}
		if s.keys == nil {
			s.keys = map[int64][]byte{}
		}
		s.keys[t.ID] = t.Key
		a := totp.Imported{ID: t.ID, UserID: t.UserID, Label: t.Label, Base32: t.Base32, Active: t.Active, LastAcceptedStep: t.LastStep}
		tt := times[t.ID]
		if a.CreatedAt, err = dbTime(tt[0]); err == nil {
			if a.ActivatedAt, err = dbTime(tt[1]); err == nil {
				a.LastUsedAt, err = dbTime(tt[2])
			}
		}
		if err != nil {
			return &StepError{UserID: t.UserID, Record: fmt.Sprint(t.ID), Err: err}
		}
		s.authenticators = append(s.authenticators, a)
	}
	return nil
}

// totpTimes reads created_at, activated_at and last_used_at of every
// authenticator as stored text.
func totpTimes(ctx context.Context, src *Source) (map[int64][3]sql.NullString, error) {
	out := map[int64][3]sql.NullString{}
	if !src.schema.HasTable("totp_authenticators") {
		return out, nil
	}
	rows, err := src.db.QueryContext(ctx, `SELECT id, CAST(created_at AS TEXT), CAST(activated_at AS TEXT), CAST(last_used_at AS TEXT) FROM totp_authenticators`)
	if err != nil {
		return nil, fmt.Errorf("legacy: read TOTP authenticators: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var t [3]sql.NullString
		if err := rows.Scan(&id, &t[0], &t[1], &t[2]); err != nil {
			return nil, fmt.Errorf("legacy: read TOTP authenticators: %w", err)
		}
		out[id] = t
	}
	return out, rows.Err()
}

func (s *totpStep) Write(ctx context.Context, tx *store.Tx, seal Sealer) error {
	ring, err := ringOf(seal)
	if err != nil {
		return err
	}
	svc := &totp.Service{Ring: ring}
	for _, a := range s.authenticators {
		if err := svc.ImportTx(ctx, tx, a); err != nil {
			return &StepError{UserID: a.UserID, Record: fmt.Sprint(a.ID), Err: err}
		}
	}
	return nil
}

// Verify opens every stored secret and compares it and the replay state
// with the legacy record; the codes it yields are the legacy codes.
func (s *totpStep) Verify(ctx context.Context, tx *store.Tx, open Opener) error {
	ring, err := ringOf(open)
	if err != nil {
		return err
	}
	svc := &totp.Service{Ring: ring}
	for _, want := range s.authenticators {
		got, err := svc.ExportTx(ctx, tx, want.ID)
		if err != nil {
			return &StepError{UserID: want.UserID, Record: fmt.Sprint(want.ID), Err: err}
		}
		same := got.UserID == want.UserID && got.Label == want.Label && got.Base32 == want.Base32 &&
			got.Active == want.Active && got.LastAcceptedStep == want.LastAcceptedStep && got.CreatedAt.Equal(want.CreatedAt) &&
			got.ActivatedAt.Equal(want.ActivatedAt) && got.LastUsedAt.Equal(want.LastUsedAt)
		key, err := otp.DecodeSecret(got.Base32)
		if err == nil && same {
			same = sameCodes(key, s.keys[want.ID])
		}
		if err != nil || !same {
			return &StepError{UserID: want.UserID, Record: fmt.Sprint(want.ID), Err: errors.Join(errors.New("legacy: the stored TOTP authenticator differs"), err)}
		}
	}
	return nil
}

func (s *totpStep) Report() StepReport {
	return StepReport{Entity: "E08", Version: 1, Read: len(s.authenticators), Written: len(s.authenticators)}
}

// sameCodes reports whether two secrets yield the same codes for a few
// fixed time steps: the stored secret produces the codes the user's
// authenticator app produces.
func sameCodes(stored, legacy []byte) bool {
	for _, step := range []uint64{0, 1, 59787003, 1 << 32} {
		a, err1 := otp.TOTP(stored, step)
		b, err2 := otp.TOTP(legacy, step)
		if err1 != nil || err2 != nil || a != b {
			return false
		}
	}
	return true
}
