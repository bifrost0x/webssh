package stepup

import (
	"context"
	"encoding/json/jsontext"
	"errors"
	"log/slog"
	"slices"
	"time"

	"github.com/bifrost0x/webssh/internal/auth"
	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/store"
)

// Lifetimes and limits of app/step_up.py.
const (
	GrantTTL          = 5 * time.Minute
	IntentTTL         = 5 * time.Minute
	MaxGrantsPerSess  = 32
	MaxIntentsPerSess = 8
	MaxTargetBytes    = 1024
	maxTokenBytes     = 256
)

// Proof methods.
const (
	MethodPassword = "password"
	MethodTOTP     = "totp"
	MethodPasskey  = "passkey"
	MethodRecent   = "recent"
)

// SessionAssurance is how and when a browser session was authenticated.
type SessionAssurance struct {
	Level auth.Assurance
	// StrongAt is the last MFA or passkey authentication of the session;
	// zero if there was none.
	StrongAt time.Time
	// Methods are the authentication methods of the session
	// ("password", "totp", "passkey", "recovery_code", …).
	Methods []string
}

// Sessions reads the assurance of a browser session (internal/session). It
// fails when the session is no longer valid.
type Sessions interface {
	Assurance(ctx context.Context, p principal.Principal) (SessionAssurance, error)
}

// Passwords checks the account password again (internal/auth/local).
// HasPassword is false for accounts managed by a directory or provider.
// VerifyPassword takes the same time for every wrong password.
type Passwords interface {
	HasPassword(ctx context.Context, userID int64) (bool, error)
	VerifyPassword(ctx context.Context, userID int64, password string) (bool, error)
}

// TOTP checks a code of the account's authenticators under the step-up
// backoff (internal/auth/totp).
type TOTP interface {
	Enrolled(ctx context.Context, userID int64) (bool, error)
	CheckCode(ctx context.Context, userID int64, code string, scope auth.Scope) error
}

// Passkeys runs a passkey assertion (internal/auth/webauthn). binding ties
// the challenge to one intent of one browser session.
type Passkeys interface {
	Enrolled(ctx context.Context, userID int64) (bool, error)
	AssertionOptions(ctx context.Context, userID int64, binding string) (jsontext.Value, error)
	VerifyAssertion(ctx context.Context, userID int64, binding string, credential jsontext.Value) error
}

// TargetCheck validates a target of one action for p, e.g. that a factor
// to delete belongs to p's account.
type TargetCheck func(ctx context.Context, p principal.Principal, target string) error

// Service is the one step-up service (ADR 0011).
type Service struct {
	DB        *store.DB
	Ring      *keyring.Ring
	Sessions  Sessions
	Accounts  auth.Accounts
	Gates     auth.Gates
	Passwords Passwords
	TOTP      TOTP
	// Passkeys is nil until passkeys are built; the method is then never
	// offered.
	Passkeys Passkeys
	// Targets holds the extra target checks per action.
	Targets map[principal.Action]TargetCheck
	// RecentWindow is STEP_UP_MAX_AGE_SECONDS: a session authenticated with
	// MFA or a passkey that recently gets a grant without a new proof.
	RecentWindow time.Duration
	Now          func() time.Time
	Audit        auth.Audit
	Logger       *slog.Logger
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func (s *Service) audit() auth.Audit { return auth.AuditOrLog(s.Audit, s.Logger) }

var (
	// ErrInvalid is a request that names no valid action or target.
	ErrInvalid = fault.New(fault.InvalidRequest, "Invalid step-up request")
	// ErrFailed ends a step-up prompt: no method, expired intent, refused.
	ErrFailed = fault.New(fault.StepUpFailed, "Step-up authentication failed")
	// errWrongSecret marks a wrong password or code, which may be retried.
	errWrongSecret = errors.New("stepup: wrong secret")
	// ErrRequired is every refusal of Consume.
	ErrRequired = fault.New(fault.StepUpRequired, "Additional authentication is required")
)

// Rejected reports whether err is a wrong password or code that the
// prompt may retry.
func Rejected(err error) bool { return errors.Is(err, errWrongSecret) }

func rejected() error {
	return fault.Wrap(fault.StepUpFailed, errWrongSecret, "Step-up authentication failed")
}

// adminActions need an administrator.
var adminActions = []principal.Action{principal.ActionSecurityFeatureUpdate, principal.ActionUserCreate}

// selfActions target the principal's own account; the target defaults to
// the user id and must equal it. key.upload is one of them: the page
// sends no target and the vault binds the grant to the user id.
var selfActions = []principal.Action{
	principal.ActionTOTPEnroll, principal.ActionPasskeyEnroll, principal.ActionMFAEnable,
	principal.ActionMFADisable, principal.ActionRecoveryRotate, principal.ActionKeyUpload,
}

// actionFeature is the security feature an action needs.
var actionFeature = map[principal.Action]string{
	principal.ActionTOTPEnroll:     auth.FeatureTOTP,
	principal.ActionTOTPDelete:     auth.FeatureTOTP,
	principal.ActionPasskeyEnroll:  auth.FeaturePasskey,
	principal.ActionPasskeyDelete:  auth.FeaturePasskey,
	principal.ActionMFAEnable:      auth.FeaturePasskey,
	principal.ActionRecoveryRotate: auth.FeatureRecovery,
}

// Plan is what a step-up for one action and target needs.
type Plan struct {
	Required auth.Assurance
	Methods  []string
	// Grant is set when the session's recent strong authentication suffices.
	Grant string
}

// checkTarget validates action and target for p and returns the target to
// bind.
func (s *Service) checkTarget(ctx context.Context, p principal.Principal, action principal.Action, target string) (string, error) {
	if !action.Known() || slices.Contains(adminActions, action) && !p.IsAdmin {
		return "", ErrInvalid
	}
	self := itoa(p.UserID)
	if slices.Contains(selfActions, action) {
		if target == "" {
			target = self
		}
		if target != self {
			return "", ErrInvalid
		}
	}
	if target == "" || len(target) > MaxTargetBytes {
		return "", ErrInvalid
	}
	if feature, ok := actionFeature[action]; ok {
		if on, err := s.active(ctx, feature); err != nil {
			return "", err
		} else if !on {
			return "", ErrInvalid
		}
	}
	if err := s.checkMFAState(ctx, p, action); err != nil {
		return "", err
	}
	if check := s.Targets[action]; check != nil {
		if err := check(ctx, p, target); err != nil {
			return "", ErrInvalid
		}
	}
	return target, nil
}

// checkMFAState refuses turning MFA off when it is off and on when it is
// on, like the Python intents.
func (s *Service) checkMFAState(ctx context.Context, p principal.Principal, action principal.Action) error {
	if action != principal.ActionMFADisable && action != principal.ActionMFAEnable {
		return nil
	}
	on, err := s.mfaRequired(ctx, p.UserID)
	if err != nil {
		return err
	}
	if on == (action == principal.ActionMFAEnable) {
		return ErrInvalid
	}
	if action == principal.ActionMFAEnable {
		ok, err := s.passkeysEnrolled(ctx, p.UserID)
		if err != nil {
			return err
		}
		if !ok {
			return ErrInvalid
		}
	}
	return nil
}

func (s *Service) active(ctx context.Context, feature string) (bool, error) {
	if s.Gates == nil {
		return false, nil
	}
	return s.Gates.Active(ctx, feature)
}

func (s *Service) mfaRequired(ctx context.Context, userID int64) (bool, error) {
	var on bool
	err := s.DB.Read(ctx, func(tx *store.Tx) error {
		var err error
		on, err = s.Accounts.MFARequired(ctx, tx, userID)
		return err
	})
	return on, err
}

func (s *Service) required(ctx context.Context, userID int64) (auth.Assurance, error) {
	on, err := s.mfaRequired(ctx, userID)
	if err != nil {
		return "", err
	}
	if on {
		return auth.AssuranceMFA, nil
	}
	return auth.AssuranceBasic, nil
}

func (s *Service) passkeysEnrolled(ctx context.Context, userID int64) (bool, error) {
	if s.Passkeys == nil {
		return false, nil
	}
	if on, err := s.active(ctx, auth.FeaturePasskey); err != nil || !on {
		return false, err
	}
	return s.Passkeys.Enrolled(ctx, userID)
}

// methods returns the proofs that reach required for p, most preferred
// first: with MFA on a passkey or TOTP, otherwise the password, or a
// passkey for accounts without one. A recovery session has none; it may
// only repair its factors, which needs no grant.
func (s *Service) methods(ctx context.Context, p principal.Principal, sa SessionAssurance, required auth.Assurance) ([]string, error) {
	if p.Recovery || slices.Contains(sa.Methods, "recovery_code") {
		return nil, nil
	}
	passkey, err := s.passkeysEnrolled(ctx, p.UserID)
	if err != nil {
		return nil, err
	}
	if required == auth.AssuranceMFA {
		var out []string
		if passkey {
			out = append(out, MethodPasskey)
		}
		if on, err := s.active(ctx, auth.FeatureTOTP); err != nil {
			return nil, err
		} else if on && s.TOTP != nil {
			if ok, err := s.TOTP.Enrolled(ctx, p.UserID); err != nil {
				return nil, err
			} else if ok {
				out = append(out, MethodTOTP)
			}
		}
		return out, nil
	}
	if slices.Contains(sa.Methods, "password") && s.Passwords != nil {
		if ok, err := s.Passwords.HasPassword(ctx, p.UserID); err != nil {
			return nil, err
		} else if ok {
			return []string{MethodPassword}, nil
		}
	}
	if passkey {
		return []string{MethodPasskey}, nil
	}
	return nil, nil
}

// assurance returns the level a proof method reaches.
func assurance(method string) auth.Assurance {
	switch method {
	case MethodPasskey:
		return auth.AssurancePhishingResistant
	case MethodTOTP:
		return auth.AssuranceMFA
	default:
		return auth.AssuranceBasic
	}
}

// recent returns the session's level if a strong authentication happened
// within RecentWindow.
func (s *Service) recent(sa SessionAssurance, now time.Time) (auth.Assurance, bool) {
	if sa.StrongAt.IsZero() || sa.Level.Rank() <= auth.AssuranceBasic.Rank() {
		return "", false
	}
	age := now.Sub(sa.StrongAt)
	return sa.Level, age >= 0 && age <= s.RecentWindow
}

// Plan checks action and target for p and returns the methods that can
// confirm it, or a grant at once when the session authenticated strongly
// within RecentWindow.
func (s *Service) Plan(ctx context.Context, p principal.Principal, action principal.Action, target, channel string) (Plan, string, error) {
	return s.plan(ctx, p, action, target, channel, true)
}

func (s *Service) plan(ctx context.Context, p principal.Principal, action principal.Action, target, channel string, allowRecent bool) (Plan, string, error) {
	if !p.Valid() {
		return Plan{}, "", fault.New(fault.AuthenticationNeeded, "")
	}
	target, err := s.checkTarget(ctx, p, action, target)
	if err != nil {
		return Plan{}, "", err
	}
	sa, err := s.Sessions.Assurance(ctx, p)
	if err != nil {
		return Plan{}, "", ErrFailed
	}
	required, err := s.required(ctx, p.UserID)
	if err != nil {
		return Plan{}, "", err
	}
	plan := Plan{Required: required}
	if level, ok := s.recent(sa, s.now()); allowRecent && ok && !p.Recovery && level.Rank() >= required.Rank() {
		plan.Grant, err = s.issue(ctx, p, action, target, level, channel)
		return plan, target, err
	}
	if plan.Methods, err = s.methods(ctx, p, sa, required); err != nil {
		return Plan{}, "", err
	}
	if len(plan.Methods) == 0 {
		return Plan{}, "", ErrFailed
	}
	return plan, target, nil
}
