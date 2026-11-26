package totp

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/bifrost0x/webssh/internal/auth"
	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/qrcode"
	"github.com/bifrost0x/webssh/internal/store"
)

// Enrollment is the one-time setup view of a new authenticator. Secret is
// shown once; the server keeps it sealed for EnrollmentTTL.
type Enrollment struct {
	Token           string
	Secret          string
	ProvisioningURI string
	QRSVG           string
	ExpiresAt       time.Time
}

// Activation is the result of a verified first code.
type Activation struct {
	AuthenticatorID int64
	// RecoveryCodes are the new codes when this turned MFA on, else empty.
	RecoveryCodes []string
}

var (
	errLabel      = fault.New(fault.InvalidValue, "Authenticator label is invalid")
	errEnrollment = fault.New(fault.InvalidRequest, "TOTP enrollment could not be verified")
)

// quote percent-encodes like Python's urllib.parse.quote with safe="/".
func quote(s string) string {
	var b strings.Builder
	for i := range len(s) {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9',
			c == '_', c == '.', c == '-', c == '~', c == '/':
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// ProvisioningURI returns the otpauth URI of app/totp_service.py. The
// secret is base32 and the issuer fixed, so the query needs no escaping.
func ProvisioningURI(secret, account string) string {
	return "otpauth://totp/" + quote(Issuer) + ":" + quote(account) + "?secret=" + secret + "&issuer=" + Issuer
}

// Begin starts an enrolment for the principal's account, bound to its
// browser session, and returns the setup view. The caller has consumed
// the totp.enroll grant (or the session is a recovery session).
func (s *Service) Begin(ctx context.Context, p principal.Principal, label string) (Enrollment, error) {
	now := s.now()
	e := Enrollment{Token: randomToken(), Secret: newSecret(), ExpiresAt: now.Add(EnrollmentTTL)}
	e.ProvisioningURI = ProvisioningURI(e.Secret, p.Username)
	code, err := qrcode.Encode([]byte(e.ProvisioningURI), qrcode.M)
	if err != nil {
		return Enrollment{}, fmt.Errorf("totp: QR code: %w", err)
	}
	e.QRSVG = qrcode.SVG(code)
	err = s.DB.Write(ctx, func(tx *store.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM totp_enrollments WHERE expires_at <= ?`, now.UnixMicro()); err != nil {
			return fmt.Errorf("totp: expire enrolments: %w", err)
		}
		// Keep the newest MaxEnrollments-1 of the user, then add this one.
		if _, err := tx.ExecContext(ctx, `DELETE FROM totp_enrollments WHERE user_id = ? AND id NOT IN (
			SELECT id FROM totp_enrollments WHERE user_id = ? ORDER BY created_at DESC, id DESC LIMIT ?)`,
			p.UserID, p.UserID, MaxEnrollments-1); err != nil {
			return fmt.Errorf("totp: limit enrolments: %w", err)
		}
		var id int64
		if err := tx.QueryRowContext(ctx, `INSERT INTO totp_enrollments (token_hash, user_id, binding_hash, sealed_secret, label, created_at, expires_at)
			VALUES (?, ?, ?, x'', ?, ?, ?) RETURNING id`, digest(e.Token), p.UserID, digest(p.SessionID), label,
			now.UnixMicro(), e.ExpiresAt.UnixMicro()).Scan(&id); err != nil {
			return fmt.Errorf("totp: store enrolment: %w", err)
		}
		sealed, err := s.seal("totp_enrollments", id, p.UserID, e.Secret)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `UPDATE totp_enrollments SET sealed_secret = ? WHERE id = ?`, sealed, id)
		return err
	})
	if err != nil {
		return Enrollment{}, err
	}
	return e, nil
}

// Activate checks the first code of an enrolment of the principal's
// session and turns it into an authenticator. The first authenticator of
// an account without MFA turns MFA on and replaces the recovery codes; in
// a recovery session it ends the restriction. All of it commits together.
func (s *Service) Activate(ctx context.Context, p principal.Principal, token, code string) (Activation, error) {
	now := s.now()
	var out Activation
	err := s.DB.Write(ctx, func(tx *store.Tx) error {
		var id, userID, created int64
		var storedLabel string
		var sealed []byte
		err := tx.QueryRowContext(ctx, `SELECT id, user_id, label, sealed_secret, created_at FROM totp_enrollments
			WHERE token_hash = ? AND binding_hash = ? AND expires_at > ?`, digest(token), digest(p.SessionID), now.UnixMicro()).
			Scan(&id, &userID, &storedLabel, &sealed, &created)
		if errors.Is(err, sql.ErrNoRows) || err == nil && userID != p.UserID {
			return errEnrollment
		}
		if err != nil {
			return fmt.Errorf("totp: read enrolment: %w", err)
		}
		n, err := s.Count(ctx, tx, p.UserID)
		if err != nil {
			return err
		}
		if n >= MaxAuthenticators {
			return errEnrollment
		}
		key, err := s.open("totp_enrollments", id, userID, sealed)
		if err != nil {
			return errEnrollment
		}
		step, ok := acceptedStep(key, code, now)
		if !ok {
			return errEnrollment
		}
		label, ok := NormalizeLabel(storedLabel, true)
		if !ok {
			return errEnrollment
		}
		required, err := s.MFA.Accounts.MFARequired(ctx, tx, p.UserID)
		if err != nil {
			return err
		}
		if err := tx.QueryRowContext(ctx, `INSERT INTO totp_authenticators (user_id, label, sealed_secret, active, last_accepted_step, created_at, activated_at)
			VALUES (?, ?, x'', 1, ?, ?, ?) RETURNING id`, p.UserID, label, int64(step), created, now.UnixMicro()). // #nosec G115 -- a time step fits in int64
			Scan(&out.AuthenticatorID); err != nil {
			return fmt.Errorf("totp: store authenticator: %w", err)
		}
		if err := s.storeSecret(ctx, tx, out.AuthenticatorID, p.UserID, key); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM totp_enrollments WHERE id = ?`, id); err != nil {
			return fmt.Errorf("totp: finish enrolment: %w", err)
		}
		if !required {
			if out.RecoveryCodes, err = s.Recovery.ReplaceTx(ctx, tx, p.UserID, auth.RecoveryCodeCount); err != nil {
				return err
			}
		}
		if err := s.MFA.Accounts.SetMFARequired(ctx, tx, p.UserID, true); err != nil {
			return err
		}
		if err := auth.ClearTx(ctx, tx, p.UserID); err != nil {
			return err
		}
		if p.Recovery {
			return s.MFA.Sessions.EndRecovery(ctx, tx, p.SessionID, "totp", false)
		}
		return nil
	})
	if err != nil {
		return Activation{}, err
	}
	return out, nil
}

func (s *Service) storeSecret(ctx context.Context, tx *store.Tx, id, userID int64, key []byte) error {
	secret := encodeSecret(key)
	sealed, err := s.seal("totp_authenticators", id, userID, secret)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE totp_authenticators SET sealed_secret = ? WHERE id = ?`, sealed, id); err != nil {
		return fmt.Errorf("totp: store authenticator secret: %w", err)
	}
	return nil
}
