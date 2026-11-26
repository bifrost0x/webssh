package webauthn

import (
	"context"
	"database/sql"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/store"
)

// Credential is a passkey as the Security page lists it.
type Credential struct {
	ID         int64
	Name       string
	CreatedAt  time.Time
	LastUsedAt time.Time // zero if never used
}

var (
	errNotFound   = fault.New(fault.NotFound, "Passkey not found")
	errLastFactor = fault.New(fault.LastFactorRequired, "Add a replacement factor or disable MFA first")
)

// Count implements auth.DurableFactor: the passkeys of userID.
func (s *Service) Count(ctx context.Context, tx *store.Tx, userID int64) (int, error) {
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM webauthn_credentials WHERE user_id = ?`, userID).Scan(&n); err != nil {
		return 0, fmt.Errorf("webauthn: count passkeys: %w", err)
	}
	return n, nil
}

// Enrolled reports whether userID has a passkey (stepup.Passkeys,
// auth.Factor).
func (s *Service) Enrolled(ctx context.Context, userID int64) (bool, error) {
	var n int
	err := s.DB.Read(ctx, func(tx *store.Tx) error {
		var err error
		n, err = s.Count(ctx, tx, userID)
		return err
	})
	return n > 0, err
}

// List returns the passkeys of userID in id order.
func (s *Service) List(ctx context.Context, userID int64) ([]Credential, error) {
	var out []Credential
	err := s.DB.Read(ctx, func(tx *store.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT id, name, created_at, last_used_at FROM webauthn_credentials
			WHERE user_id = ? ORDER BY id`, userID)
		if err != nil {
			return fmt.Errorf("webauthn: list passkeys: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var c Credential
			var created int64
			var used sql.NullInt64
			if err := rows.Scan(&c.ID, &c.Name, &created, &used); err != nil {
				return fmt.Errorf("webauthn: list passkeys: %w", err)
			}
			c.CreatedAt = time.UnixMicro(created).UTC()
			if used.Valid {
				c.LastUsedAt = time.UnixMicro(used.Int64).UTC()
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	return out, err
}

// credentialIDs returns the raw credential IDs of userID in id order.
func credentialIDs(ctx context.Context, tx *store.Tx, userID int64) ([][]byte, error) {
	rows, err := tx.QueryContext(ctx, `SELECT credential_id FROM webauthn_credentials WHERE user_id = ? ORDER BY id`, userID)
	if err != nil {
		return nil, fmt.Errorf("webauthn: read credential ids: %w", err)
	}
	defer rows.Close()
	var out [][]byte
	for rows.Next() {
		var id []byte
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("webauthn: read credential ids: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

func (s *Service) credentialIDs(ctx context.Context, userID int64) ([][]byte, error) {
	var ids [][]byte
	err := s.DB.Read(ctx, func(tx *store.Tx) error {
		var err error
		ids, err = credentialIDs(ctx, tx, userID)
		return err
	})
	return ids, err
}

// record is a stored credential as an assertion needs it.
type record struct {
	id, userID int64
	stored     Stored
}

// lookup finds the credential with the raw ID credID; with userID other
// than 0 it must belong to that account.
func (s *Service) lookup(ctx context.Context, credID []byte, userID int64) (record, error) {
	var r record
	var cose []byte
	var count int64
	var be sql.NullBool
	err := s.DB.Read(ctx, func(tx *store.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT id, user_id, public_key, sign_count, backup_eligible FROM webauthn_credentials
			WHERE credential_id = ?`, credID).Scan(&r.id, &r.userID, &cose, &count, &be)
	})
	if errors.Is(err, sql.ErrNoRows) || err == nil && userID != 0 && r.userID != userID {
		return record{}, errNotFound
	}
	if err != nil {
		return record{}, fmt.Errorf("webauthn: read passkey: %w", err)
	}
	key, err := ParseCOSEKey(cose)
	if err != nil {
		return record{}, fmt.Errorf("webauthn: passkey %d: %w", r.id, err)
	}
	r.stored = Stored{Key: key, SignCount: uint32(count), UserHandle: UserHandle(r.userID)} // #nosec G115 -- the column is checked to fit uint32
	if be.Valid {
		r.stored.BackupEligible = &be.Bool
	}
	return r, nil
}

// recordUse stores the outcome of a verified assertion. The counter only
// changes from the value the assertion was checked against, so of two
// concurrent uses of one assertion or counter value only one succeeds.
// A migrated credential learns its backup eligibility on first use.
func (s *Service) recordUse(ctx context.Context, tx *store.Tx, r record, v Verified) error {
	res, err := tx.ExecContext(ctx, `UPDATE webauthn_credentials SET sign_count = max(sign_count, ?), last_used_at = ?,
		backup_eligible = coalesce(backup_eligible, ?), backup_state = ? WHERE id = ? AND sign_count = ?`,
		int64(v.SignCount), s.now().UnixMicro(), v.Flags&FlagBE != 0, v.Flags&FlagBS != 0, r.id, int64(r.stored.SignCount))
	if err != nil {
		return fmt.Errorf("webauthn: record passkey use: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		return errors.Join(errCounter, err)
	}
	return nil
}

// Owned reports whether id is a passkey of userID.
func (s *Service) Owned(ctx context.Context, userID, id int64) (bool, error) {
	var owner int64
	err := s.DB.Read(ctx, func(tx *store.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT user_id FROM webauthn_credentials WHERE id = ?`, id).Scan(&owner)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("webauthn: read passkey: %w", err)
	}
	return owner == userID, nil
}

// OwnsTarget is the step-up target check of passkey.delete: the target is
// the id of one of p's passkeys.
func (s *Service) OwnsTarget(ctx context.Context, p principal.Principal, target string) error {
	id, err := strconv.ParseInt(target, 10, 64)
	if err != nil || id <= 0 || strconv.FormatInt(id, 10) != target {
		return errNotFound
	}
	owned, err := s.Owned(ctx, p.UserID, id)
	if err != nil {
		return err
	}
	if !owned {
		return errNotFound
	}
	return nil
}

// Delete removes the principal's passkey id. With MFA on, the last usable
// factor cannot be removed. The caller has consumed the passkey.delete
// grant for id.
func (s *Service) Delete(ctx context.Context, p principal.Principal, id int64) error {
	return s.DB.Write(ctx, func(tx *store.Tx) error {
		var owner int64
		err := tx.QueryRowContext(ctx, `SELECT user_id FROM webauthn_credentials WHERE id = ?`, id).Scan(&owner)
		if errors.Is(err, sql.ErrNoRows) || err == nil && owner != p.UserID {
			return errNotFound
		}
		if err != nil {
			return fmt.Errorf("webauthn: read passkey: %w", err)
		}
		mfaOn, err := s.MFA.Accounts.MFARequired(ctx, tx, p.UserID)
		if err != nil {
			return err
		}
		counts, err := s.MFA.CountsTx(ctx, tx, p.UserID)
		if err != nil {
			return err
		}
		remaining := counts.Total
		if counts.Passkeys > 0 {
			remaining--
		}
		if mfaOn && remaining == 0 {
			return errLastFactor
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM webauthn_credentials WHERE id = ?`, id); err != nil {
			return fmt.Errorf("webauthn: delete passkey: %w", err)
		}
		return nil
	})
}

// Imported is a passkey taken over by the migration (E10). The credential
// ID and the COSE key are the bytes the Python release stored.
type Imported struct {
	ID, UserID   int64
	CredentialID []byte
	COSEKey      []byte
	SignCount    int64
	Transports   []string
	Name         string
	CreatedAt    time.Time
	LastUsedAt   time.Time // zero if never used
}

// ImportTx stores a migrated passkey with its legacy id after checking
// that its key parses. Backup eligibility stays unknown until first use.
func (s *Service) ImportTx(ctx context.Context, tx *store.Tx, p Imported) error {
	if _, err := ParseCOSEKey(p.COSEKey); err != nil {
		return fmt.Errorf("webauthn: passkey %d: %w", p.ID, err)
	}
	if p.Transports == nil {
		p.Transports = []string{}
	}
	transports, err := json.Marshal(p.Transports)
	if err != nil {
		return fmt.Errorf("webauthn: passkey %d: transports: %w", p.ID, err)
	}
	var used any
	if !p.LastUsedAt.IsZero() {
		used = p.LastUsedAt.UnixMicro()
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO webauthn_credentials (id, user_id, credential_id, public_key, sign_count, transports, name,
		created_at, last_used_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		p.ID, p.UserID, p.CredentialID, p.COSEKey, p.SignCount, string(transports), p.Name, p.CreatedAt.UnixMicro(), used)
	if err != nil {
		return fmt.Errorf("webauthn: import passkey %d: %w", p.ID, err)
	}
	return nil
}
