package auth

import (
	"context"
	"log/slog"

	"github.com/bifrost0x/webssh/internal/store"
)

// Assurance is the strength of a sign-in or a step-up proof. The values
// are those the Python release stores and are compared by rank.
type Assurance string

// Assurance levels.
const (
	AssuranceBasic             Assurance = "BASIC"              // password or provider sign-in
	AssuranceMFA               Assurance = "MFA"                // plus TOTP or a recovery code
	AssurancePhishingResistant Assurance = "PHISHING_RESISTANT" // a passkey
)

// Rank orders the levels; unknown values rank below BASIC.
func (a Assurance) Rank() int {
	switch a {
	case AssuranceBasic:
		return 0
	case AssuranceMFA:
		return 1
	case AssurancePhishingResistant:
		return 2
	default:
		return -1
	}
}

// Security features gated by the administrator (internal/operations).
const (
	FeatureTOTP     = "totp"
	FeaturePasskey  = "passkey"
	FeatureRecovery = "recovery"
)

// Gates says whether a security feature is active: allowed by the
// deployment and enabled by an administrator (internal/operations).
type Gates interface {
	Active(ctx context.Context, feature string) (bool, error)
}

// Accounts holds the per-account "MFA required" flag (internal/accounts).
// Both methods run inside the caller's write transaction, so a factor
// change and the flag change commit together.
type Accounts interface {
	MFARequired(ctx context.Context, tx *store.Tx, userID int64) (bool, error)
	SetMFARequired(ctx context.Context, tx *store.Tx, userID int64, required bool) error
}

// DurableFactor is an enrolled second factor kind that counts towards
// "at least one factor remains" (TOTP authenticators, passkeys).
type DurableFactor interface {
	Count(ctx context.Context, tx *store.Tx, userID int64) (int, error)
}

// FactorRemover removes every factor of one kind of a user. Turning MFA
// off removes the TOTP authenticators; passkeys stay as sign-in factors.
type FactorRemover interface {
	RemoveAll(ctx context.Context, tx *store.Tx, userID int64) error
}

// RecoverySessions ends the recovery restriction of a browser session
// (internal/session). replacement names the factor the user enrolled
// ("totp", "passkey") or is empty when MFA was turned off; basic lowers
// the session's assurance to BASIC. It runs in the caller's transaction.
type RecoverySessions interface {
	EndRecovery(ctx context.Context, tx *store.Tx, sessionID, replacement string, basic bool) error
}

// Audit writes security events (internal/audit). fields are key-value
// pairs; they never carry secrets.
type Audit interface {
	Security(ctx context.Context, level slog.Level, event string, fields ...any)
}

// AuditOrLog returns a, or one that writes to logger.
func AuditOrLog(a Audit, logger *slog.Logger) Audit {
	if a != nil {
		return a
	}
	return logAudit{logger}
}

type logAudit struct{ logger *slog.Logger }

func (l logAudit) Security(ctx context.Context, level slog.Level, event string, fields ...any) {
	logger := l.logger
	if logger == nil {
		logger = slog.Default()
	}
	logger.Log(ctx, level, event, fields...)
}
