package legacy

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/bifrost0x/webssh/internal/store"
)

// signInStateTables hold the short-lived sign-in state of entity E13.
var signInStateTables = []string{"pending_authentications", "step_up_grants", "step_up_intents",
	"factor_bootstrap_tokens", "github_oauth_states", "oidc_login_states", "webauthn_challenges"}

// transientStep accounts for entity E13 (DISCARD, D-02): pending
// sign-ins, step-up grants and intents, factor bootstrap codes, OAuth and
// OIDC states and WebAuthn challenges are not taken over. Unexpired
// bootstrap codes are listed per account, by action and without the
// token, so administrators can issue them again.
type transientStep struct {
	counts    map[string]int
	bootstrap []bootstrapCode
	total     int
	now       func() time.Time
}

type bootstrapCode struct {
	userID int64
	action string
}

func (*transientStep) Entity() string { return "E13" }

func (*transientStep) Version() int { return 1 }

func (s *transientStep) Read(ctx context.Context, src *Source) error {
	s.counts = map[string]int{}
	for _, t := range signInStateTables {
		n, err := countTable(ctx, src, t)
		if err != nil {
			return err
		}
		s.counts[t] = n
		s.total += n
	}
	if !src.schema.HasTable("factor_bootstrap_tokens") || src.emptiedByRestore("factor_bootstrap_tokens") {
		return nil
	}
	rows, err := src.db.QueryContext(ctx, `SELECT user_id, action, CAST(expires_at AS TEXT) FROM factor_bootstrap_tokens ORDER BY id`)
	if err != nil {
		return fmt.Errorf("legacy: read factor bootstrap codes: %w", err)
	}
	defer rows.Close()
	now := time.Now()
	if s.now != nil {
		now = s.now()
	}
	for rows.Next() {
		var b bootstrapCode
		var expires sql.NullString
		if err := rows.Scan(&b.userID, &b.action, &expires); err != nil {
			return fmt.Errorf("legacy: read factor bootstrap codes: %w", err)
		}
		at, err := dbTime(expires)
		if err != nil {
			return &StepError{UserID: b.userID, Err: err}
		}
		if at.After(now) {
			s.bootstrap = append(s.bootstrap, b)
		}
	}
	return rows.Err()
}

func (*transientStep) Write(context.Context, *store.Tx, Sealer) error { return nil }

func (*transientStep) Verify(context.Context, *store.Tx, Opener) error { return nil }

func (s *transientStep) Report() StepReport {
	r := StepReport{Entity: "E13", Version: 1, Read: s.total, Discarded: s.total,
		Notes: []string{"pending sign-ins, step-up grants, bootstrap codes and sign-in states are not taken over"}}
	for _, t := range signInStateTables {
		if s.counts[t] > 0 {
			r.Notes = append(r.Notes, fmt.Sprintf("%s: %d discarded", t, s.counts[t]))
		}
	}
	for _, b := range s.bootstrap {
		r.UserActions = append(r.UserActions, UserAction{UserID: b.userID,
			Action: "an unused factor bootstrap code for " + b.action + " was not taken over; an administrator issues a new one"})
	}
	return r
}
