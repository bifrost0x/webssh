package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/session"
	"github.com/bifrost0x/webssh/internal/store"
)

// Pending sign-ins live five minutes; a user has at most five at a time
// (auth_assurance._PENDING_TTL, _MAX_PENDING_PER_USER).
const (
	PendingTTL     = 5 * time.Minute
	maxPendingUser = 5
)

// Pending is a sign-in between the primary credential and the second
// factor.
type Pending struct {
	UserID        int64
	Generation    int64
	PrimaryMethod string
	Assurance     session.Assurance
	Remember      bool
	Continuation  string
	ExpiresAt     time.Time
	// StrongAt is when a provider last authenticated the user strongly
	// (the OIDC auth_time of an MFA sign-in). It is not stored: a sign-in
	// that waits for a second factor is BASIC.
	StrongAt time.Time
}

var errPending = fault.New(fault.MFARestart, "")

// MAC is the part of the keyring the package uses.
type MAC interface {
	MAC(p keyring.Purpose, msg []byte) []byte
}

type pendingStore struct {
	db  *store.DB
	mac MAC
	now func() time.Time
}

func (s pendingStore) key(binding string) []byte {
	return s.mac.MAC(keyring.SessionToken, []byte("webssh-pending-v1\x00"+binding))
}

// begin stores p for the browser binding, replacing an earlier pending
// sign-in of the same browser.
func (s pendingStore) begin(ctx context.Context, binding string, p Pending) error {
	if binding == "" {
		return errPending
	}
	now := s.now()
	err := s.db.Write(ctx, func(tx *store.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM auth_pending WHERE expires_us <= ? OR binding_mac = ?`, now.UnixMicro(), s.key(binding)); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM auth_pending WHERE binding_mac IN (SELECT binding_mac FROM auth_pending
			WHERE user_id = ? ORDER BY created_us DESC LIMIT -1 OFFSET ?)`, p.UserID, maxPendingUser-1); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO auth_pending (binding_mac, user_id, auth_generation, primary_method, assurance,
			remember, continuation, created_us, expires_us) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			s.key(binding), p.UserID, p.Generation, p.PrimaryMethod, string(p.Assurance), p.Remember, p.Continuation,
			now.UnixMicro(), now.Add(PendingTTL).UnixMicro())
		return err
	})
	if err != nil {
		return fault.Wrap(fault.StorageError, fmt.Errorf("auth: store pending sign-in: %w", err), "")
	}
	return nil
}

const pendingColumns = `user_id, auth_generation, primary_method, assurance, remember, continuation, expires_us`

func scanPending(row interface{ Scan(...any) error }) (Pending, error) {
	var p Pending
	var assurance string
	var exp int64
	if err := row.Scan(&p.UserID, &p.Generation, &p.PrimaryMethod, &assurance, &p.Remember, &p.Continuation, &exp); err != nil {
		return Pending{}, err
	}
	p.Assurance = session.Assurance(assurance)
	p.ExpiresAt = time.UnixMicro(exp).UTC()
	return p, nil
}

// peek returns the valid pending sign-in of a binding without using it.
func (s pendingStore) peek(ctx context.Context, binding string) (Pending, error) {
	if binding == "" {
		return Pending{}, errPending
	}
	var p Pending
	err := s.db.Read(ctx, func(tx *store.Tx) error {
		var err error
		p, err = scanPending(tx.QueryRowContext(ctx, `SELECT `+pendingColumns+` FROM auth_pending WHERE binding_mac = ? AND expires_us > ?`,
			s.key(binding), s.now().UnixMicro()))
		return err
	})
	return p, pendingErr(err)
}

// consume removes and returns the pending sign-in of a binding; it
// succeeds at most once.
func (s pendingStore) consume(ctx context.Context, binding string) (Pending, error) {
	if binding == "" {
		return Pending{}, errPending
	}
	var p Pending
	err := s.db.Write(ctx, func(tx *store.Tx) error {
		var err error
		p, err = scanPending(tx.QueryRowContext(ctx, `DELETE FROM auth_pending WHERE binding_mac = ? AND expires_us > ? RETURNING `+pendingColumns,
			s.key(binding), s.now().UnixMicro()))
		return err
	})
	return p, pendingErr(err)
}

// cancel deletes the pending sign-in of a binding.
func (s pendingStore) cancel(ctx context.Context, binding string) error {
	if binding == "" {
		return nil
	}
	err := s.db.Write(ctx, func(tx *store.Tx) error {
		_, err := tx.ExecContext(ctx, `DELETE FROM auth_pending WHERE binding_mac = ?`, s.key(binding))
		return err
	})
	if err != nil {
		return fault.Wrap(fault.StorageError, err, "")
	}
	return nil
}

func pendingErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, sql.ErrNoRows):
		return errPending
	default:
		return fault.Wrap(fault.StorageError, err, "")
	}
}
