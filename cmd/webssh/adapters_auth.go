package main

import (
	"context"
	"encoding/json/jsontext"
	"log/slog"
	"time"

	"github.com/bifrost0x/webssh/internal/accounts"
	"github.com/bifrost0x/webssh/internal/audit"
	"github.com/bifrost0x/webssh/internal/auth"
	"github.com/bifrost0x/webssh/internal/auth/local"
	"github.com/bifrost0x/webssh/internal/auth/stepup"
	"github.com/bifrost0x/webssh/internal/auth/totp"
	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/operations"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/session"
	"github.com/bifrost0x/webssh/internal/settings"
	"github.com/bifrost0x/webssh/internal/store"
)

// mfaAccounts adapts the account store to auth.Accounts.
type mfaAccounts struct{ a *accounts.Service }

func (m mfaAccounts) MFARequired(ctx context.Context, tx *store.Tx, userID int64) (bool, error) {
	return m.a.MFARequiredTx(ctx, tx, userID)
}

func (m mfaAccounts) SetMFARequired(ctx context.Context, tx *store.Tx, userID int64, required bool) error {
	return m.a.SetMFARequiredTx(ctx, tx, userID, required)
}

// sessionAssurance adapts the session service to stepup.Sessions. The
// principal's session must still be valid.
type sessionAssurance struct{ s *session.Service }

func (a sessionAssurance) Assurance(ctx context.Context, p principal.Principal) (stepup.SessionAssurance, error) {
	sess, err := a.s.Lookup(ctx, p.SessionID)
	if err != nil {
		return stepup.SessionAssurance{}, err
	}
	if sess.UserID != p.UserID {
		return stepup.SessionAssurance{}, stepup.ErrRequired
	}
	return stepup.SessionAssurance{Level: auth.Assurance(sess.Assurance), StrongAt: sess.StrongAt, Methods: sess.Methods}, nil
}

// passwordCheck adapts the local password provider to stepup.Passwords.
// Accounts that a directory or provider manages have no local password.
type passwordCheck struct {
	p *local.Provider
	a *accounts.Service
}

func (c passwordCheck) HasPassword(ctx context.Context, userID int64) (bool, error) {
	acc, err := c.a.Get(ctx, userID)
	if err != nil {
		return false, err
	}
	return acc.Managed == accounts.ManagedLocal, nil
}

func (c passwordCheck) VerifyPassword(ctx context.Context, userID int64, password string) (bool, error) {
	return c.p.Matches(ctx, userID, password)
}

// authAudit adapts the audit log to auth.Audit: warnings and errors are
// written at WARNING, everything else at INFO.
type authAudit struct{ l *audit.Logger }

func (a authAudit) Security(_ context.Context, level slog.Level, event string, fields ...any) {
	if level >= slog.LevelWarn {
		a.l.SecurityWarning(event, fields...)
		return
	}
	a.l.Security(event, fields...)
}

// signInSettings adapts the application settings to auth.SignInSettings.
type signInSettings struct{ s *settings.Service }

func (s signInSettings) RegistrationEnabled(ctx context.Context) (bool, error) {
	app, err := s.s.App(ctx)
	return app.RegistrationEnabled, err
}

func (s signInSettings) LoginLimits(ctx context.Context) (int, int, int, error) {
	app, err := s.s.App(ctx)
	if err != nil {
		return 0, 0, 0, err
	}
	return app.SignIn.UsernameLimit, app.SignIn.UsernameGlobalLimit, app.SignIn.IPv6Prefix, nil
}

// sessionDurations adapts the account settings to session.Durations.
type sessionDurations struct{ s *settings.Service }

func (d sessionDurations) SessionMinutes(ctx context.Context, userID int64) (int, error) {
	u, err := d.s.User(ctx, userID)
	return u.SessionDurationMinutes, err
}

// featureGates adapts the security feature gates to settings.FeatureGates.
type featureGates struct{ g *operations.Gates }

func (f featureGates) FeatureActive(ctx context.Context, feature string) (bool, error) {
	return f.g.Active(ctx, feature)
}

// securityInventory lists every account with its sign-in credentials for
// the impact preview of the security feature gates (operations.Inventory).
// This preview has local passwords, TOTP and recovery codes; passkeys come
// with their capability through passkeys.
type securityInventory struct {
	db       *store.DB
	accounts *accounts.Service
	totp     *totp.Service
	passkeys func(ctx context.Context, userID int64) ([]operations.Credential, error)
}

func (s securityInventory) Accounts(ctx context.Context) ([]operations.Account, error) {
	list, err := s.accounts.List(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]operations.Account, 0, len(list))
	for _, a := range list {
		acc := operations.Account{
			ID: a.ID, CreatedAt: isoTime(a.CreatedAt), Username: a.Username, Generation: a.AuthGeneration,
			Admin: a.IsAdmin, Locked: a.IsLocked, MFA: a.MFARequired, Password: a.Managed == accounts.ManagedLocal,
			Passkey: []operations.Credential{}, TOTP: []operations.Credential{}, Recovery: []operations.Credential{},
			OIDC: []operations.Credential{},
		}
		auths, err := s.totp.List(ctx, a.ID)
		if err != nil {
			return nil, err
		}
		for _, t := range auths {
			acc.TOTP = append(acc.TOTP, operations.Credential{ID: t.ID, CreatedAt: isoTime(t.CreatedAt)})
		}
		var hasCodes bool
		if err := s.db.Read(ctx, func(tx *store.Tx) error {
			var err error
			hasCodes, err = auth.HasCodesTx(ctx, tx, a.ID)
			return err
		}); err != nil {
			return nil, err
		}
		if hasCodes {
			// The codes are one credential of the account; the impact
			// only asks whether it exists.
			acc.Recovery = append(acc.Recovery, operations.Credential{})
		}
		if s.passkeys != nil {
			if acc.Passkey, err = s.passkeys(ctx, a.ID); err != nil {
				return nil, err
			}
		}
		out = append(out, acc)
	}
	return out, nil
}

// GitHubActive is false: GitHub sign-in is not part of this preview.
func (securityInventory) GitHubActive(context.Context) (bool, error) { return false, nil }

func isoTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format("2006-01-02T15:04:05.000000")
}

// recoveryFactor lists recovery codes among the second-factor methods of
// a pending sign-in (available_mfa_methods): an account with unused codes
// is offered the recovery sign-in, which internal/auth serves on its own
// route (POST /api/auth/recovery). It never verifies anything itself.
type recoveryFactor struct{ db *store.DB }

func (recoveryFactor) Kind() string { return "recovery" }

func (f recoveryFactor) Enrolled(ctx context.Context, userID int64) (bool, error) {
	var has bool
	err := f.db.Read(ctx, func(tx *store.Tx) error {
		var err error
		has, err = auth.HasCodesTx(ctx, tx, userID)
		return err
	})
	return has, err
}

// Verify refuses: recovery codes are checked by the recovery sign-in
// route, which also opens the restricted recovery session.
func (recoveryFactor) Verify(context.Context, int64, jsontext.Value) error {
	return fault.New(fault.AuthFailed, "")
}
