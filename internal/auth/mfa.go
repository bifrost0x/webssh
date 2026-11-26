package auth

import (
	"context"
	"errors"
	"log/slog"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/store"
)

// FactorCounts are the usable durable factors of an account: those of a
// kind whose feature is active.
type FactorCounts struct {
	Passkeys int `json:"passkey_count"`
	TOTP     int `json:"totp_count"`
	Total    int `json:"total"`
}

// SecurityState is the factor state the Security page shows.
type SecurityState struct {
	MFAEnabled bool `json:"mfa_enabled"`
	FactorCounts
	CanEnableMFA  bool `json:"can_enable_mfa"`
	CanDisableMFA bool `json:"can_disable_mfa"`
}

// TOTPFactors is the TOTP store as MFA needs it (internal/auth/totp).
type TOTPFactors interface {
	DurableFactor
	FactorRemover
}

// MFA owns the account-wide second-factor state: the counts, and the one
// way to turn MFA off.
type MFA struct {
	DB       *store.DB
	Accounts Accounts
	Gates    Gates
	TOTP     TOTPFactors
	// Passkeys counts passkeys (internal/auth/webauthn); nil counts none.
	Passkeys DurableFactor
	Sessions RecoverySessions
	Audit    Audit
	Logger   *slog.Logger
}

var errStateChanged = fault.New(fault.Conflict, "The security state has changed. Reload the page.")

func (m *MFA) active(ctx context.Context, feature string) (bool, error) {
	if m.Gates == nil {
		return false, nil
	}
	return m.Gates.Active(ctx, feature)
}

// CountsTx counts the usable durable factors of userID.
func (m *MFA) CountsTx(ctx context.Context, tx *store.Tx, userID int64) (FactorCounts, error) {
	var c FactorCounts
	if on, err := m.active(ctx, FeaturePasskey); err != nil {
		return c, err
	} else if on && m.Passkeys != nil {
		if c.Passkeys, err = m.Passkeys.Count(ctx, tx, userID); err != nil {
			return c, err
		}
	}
	if on, err := m.active(ctx, FeatureTOTP); err != nil {
		return c, err
	} else if on {
		if c.TOTP, err = m.TOTP.Count(ctx, tx, userID); err != nil {
			return c, err
		}
	}
	c.Total = c.Passkeys + c.TOTP
	return c, nil
}

// State returns the factor state of userID.
func (m *MFA) State(ctx context.Context, userID int64) (SecurityState, error) {
	var s SecurityState
	recoveryOn, err := m.active(ctx, FeatureRecovery)
	if err != nil {
		return s, err
	}
	err = m.DB.Read(ctx, func(tx *store.Tx) error {
		var err error
		if s.MFAEnabled, err = m.Accounts.MFARequired(ctx, tx, userID); err != nil {
			return err
		}
		s.FactorCounts, err = m.CountsTx(ctx, tx, userID)
		return err
	})
	s.CanEnableMFA = !s.MFAEnabled && s.Passkeys > 0 && recoveryOn
	s.CanDisableMFA = s.MFAEnabled
	return s, err
}

// Disable turns MFA off for the principal's account. It is the only way
// to do so (ADR 0011); both routes that offer it call it. It removes the
// TOTP authenticators, clears the code backoff and the MFA flag in one
// transaction; passkeys stay as sign-in factors. In a recovery session it
// also ends the recovery restriction with BASIC assurance. Elsewhere the
// account must have MFA on, and the caller has consumed the mfa.disable
// grant.
func (m *MFA) Disable(ctx context.Context, p principal.Principal) error {
	if !p.Valid() {
		return fault.New(fault.AuthenticationNeeded, "")
	}
	err := m.DB.Write(ctx, func(tx *store.Tx) error {
		on, err := m.Accounts.MFARequired(ctx, tx, p.UserID)
		if err != nil {
			return err
		}
		if !on && !p.Recovery {
			return errStateChanged
		}
		if err := m.TOTP.RemoveAll(ctx, tx, p.UserID); err != nil {
			return err
		}
		if err := m.Accounts.SetMFARequired(ctx, tx, p.UserID, false); err != nil {
			return err
		}
		if err := ClearTx(ctx, tx, p.UserID); err != nil {
			return err
		}
		if p.Recovery {
			return m.Sessions.EndRecovery(ctx, tx, p.SessionID, "", true)
		}
		return nil
	})
	if err != nil {
		return err
	}
	event := "MFA_DISABLED"
	if p.Recovery {
		event = "MFA_DISABLED_AFTER_RECOVERY"
	}
	AuditOrLog(m.Audit, m.Logger).Security(ctx, slog.LevelInfo, event, "user", p.Username)
	return nil
}

// ErrStepUp is what a route answers when a grant is refused; it hides why.
var ErrStepUp = fault.New(fault.StepUpRequired, "Additional authentication is required")

// stepUpError keeps the classified step-up refusals and maps every other
// failure of the step-up service to step_up_required, so nothing about the
// grant leaks.
func stepUpError(err error) error {
	if fe, ok := fault.From(err); ok && (fe.Code == fault.Internal || fe.Code == fault.StorageError) {
		return err
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return ErrStepUp
}
