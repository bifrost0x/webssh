package stepup

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/bifrost0x/webssh/internal/auth"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/store"
)

// ExternalMethod is a proof at an identity provider (method "oidc"): the
// user signs in again there and the provider's callback completes the
// intent through ProveExternal.
type ExternalMethod interface {
	// Method is the method name the frontend sends ("oidc").
	Method() string
	// Offered reports whether p may prove itself with the method: the
	// session signed in with it, the provider is enabled and the account
	// still has an identity there (account_step_up_routes._allowed_methods).
	Offered(ctx context.Context, p principal.Principal, sa SessionAssurance) (bool, error)
	// ReachesMFA reports whether the provider's answer can carry MFA
	// assurance, so the method is offered for intents that need MFA.
	ReachesMFA() bool
}

// externalMethods returns the external methods offered to p, for an
// intent that needs MFA only those that can reach it.
func (s *Service) externalMethods(ctx context.Context, p principal.Principal, sa SessionAssurance, mfa bool) ([]string, error) {
	var out []string
	for _, m := range s.External {
		if mfa && !m.ReachesMFA() {
			continue
		}
		ok, err := m.Offered(ctx, p, sa)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, m.Method())
		}
	}
	return out, nil
}

func (s *Service) isExternal(method string) bool {
	return slices.ContainsFunc(s.External, func(m ExternalMethod) bool { return m.Method() == method })
}

// BeginExternal starts an administrator step-up at a provider: it stores
// an intent for action and target that only a proof can complete and
// checks that method is one of its methods. The returned intent travels
// in the provider's flight; the callback completes it with ProveExternal.
func (s *Service) BeginExternal(ctx context.Context, p principal.Principal, action principal.Action, target, method string) (string, error) {
	if !s.isExternal(method) {
		return "", ErrFailed
	}
	c, err := s.BeginCeremony(ctx, p, action, target, ChannelAdmin)
	if err != nil {
		return "", err
	}
	if !slices.Contains(c.Methods, method) {
		return "", ErrFailed
	}
	return c.Intent, nil
}

// ExternalIntent checks that the account intent token may be proven with
// method and returns the assurance it needs; the provider asks for
// OIDC_STEP_UP_ACR_VALUES only when that is above BASIC.
func (s *Service) ExternalIntent(ctx context.Context, p principal.Principal, token, method string) (auth.Assurance, error) {
	if token == "" || !s.isExternal(method) {
		return "", ErrFailed
	}
	in, err := s.load(ctx, p, token)
	if err != nil {
		return "", err
	}
	if err := s.allowed(ctx, p, in, method); err != nil {
		return "", err
	}
	return in.required, nil
}

// ProveExternal completes an intent with the provider's assurance and
// returns its grant. The intent must belong to p's session, be open, be
// provable with method and need no more than level. The grant of an
// account intent is also kept for the status poll of the page that
// started the redirect (ExternalStatus).
func (s *Service) ProveExternal(ctx context.Context, p principal.Principal, token, method string, level auth.Assurance) (string, error) {
	if token == "" || !s.isExternal(method) {
		return "", ErrFailed
	}
	in, err := s.load(ctx, p, token)
	if err != nil {
		return "", err
	}
	if err := s.allowed(ctx, p, in, method); err != nil {
		return "", err
	}
	if level.Rank() < in.required.Rank() || level.Rank() < auth.AssuranceBasic.Rank() {
		s.audit().Security(ctx, slog.LevelWarn, event(in.channel, "REJECTED"), "user", p.Username, "action", string(in.action), "method", method)
		return "", ErrFailed
	}
	grant := newToken()
	err = s.DB.Write(ctx, func(tx *store.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM stepup_intents WHERE id = ?`, in.id)
		if err != nil {
			return fmt.Errorf("stepup: complete intent: %w", err)
		}
		if n, err := res.RowsAffected(); err != nil || n != 1 {
			return errors.Join(ErrFailed, err)
		}
		return s.issueTx(ctx, tx, p, in.action, in.targetHash, level, grant)
	})
	if err != nil {
		return "", err
	}
	if in.channel == ChannelAccount {
		s.approved.put(string(s.mac("intent", token)), p.SessionID, grant, s.now())
	}
	s.audit().Security(ctx, slog.LevelInfo, event(in.channel, "GRANTED"), "user", p.Username, "action", string(in.action), "method", method, "assurance", string(level))
	return grant, nil
}

// ExternalStatus answers the status poll of an account intent that a
// provider proves: pending while the intent is open, the grant once
// (claimed by this call), ErrFailed for an unknown or expired intent.
func (s *Service) ExternalStatus(ctx context.Context, p principal.Principal, token string) (grant string, pending bool, err error) {
	if token == "" || len(token) > maxTokenBytes || !p.Valid() {
		return "", false, ErrFailed
	}
	if g, ok := s.approved.take(string(s.mac("intent", token)), p.SessionID, s.now()); ok {
		s.audit().Security(ctx, slog.LevelInfo, "ACCOUNT_STEP_UP_CONSUMED", "user", p.Username, "method", "provider")
		return g, false, nil
	}
	if _, err := s.load(ctx, p, token); err != nil {
		return "", false, err
	}
	return "", true, nil
}

// approvedGrants holds the grants of account intents proven at a
// provider until the page claims them, at most GrantTTL. Only the grant
// MAC is in the database, so the token itself waits here; a restart only
// makes the user prove again.
type approvedGrants struct {
	mu sync.Mutex
	m  map[string]approvedGrant
}

type approvedGrant struct {
	session, grant string
	expires        time.Time
}

const maxApprovedGrants = 1024

func (a *approvedGrants) put(key, sessionID, grant string, now time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.m == nil {
		a.m = map[string]approvedGrant{}
	}
	for k, v := range a.m {
		if !now.Before(v.expires) {
			delete(a.m, k)
		}
	}
	if len(a.m) >= maxApprovedGrants {
		return // the page times out and the user starts again
	}
	a.m[key] = approvedGrant{session: sessionID, grant: grant, expires: now.Add(GrantTTL)}
}

func (a *approvedGrants) take(key, sessionID string, now time.Time) (string, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	v, ok := a.m[key]
	if !ok || v.session != sessionID {
		return "", false
	}
	delete(a.m, key)
	return v.grant, now.Before(v.expires)
}
