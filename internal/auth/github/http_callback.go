package github

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/bifrost0x/webssh/internal/auth"
	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/store"
)

// callback is GET /auth/github/callback (github_callback): the state is
// consumed first, then the code is exchanged, the profile read and the
// organization policy applied; the flight's purpose decides the rest.
func (s *Service) callback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !s.Active(ctx) {
		http.NotFound(w, r)
		return
	}
	if s.limited(r, "github_callback") {
		writeError(w, http.StatusTooManyRequests, msgTooMany)
		return
	}
	ip := clientIP(s, r)
	f, p, err := s.callbackProfile(r)
	var ce *errConfig
	switch {
	case err == nil:
	case errors.Is(err, errOrganization):
		s.audit().Security(ctx, slog.LevelWarn, "GITHUB_ORGANIZATION_REJECTED", "ip", ip)
		writeError(w, http.StatusForbidden, msgOrgRequired)
		return
	case errors.Is(err, errState), errors.As(err, &ce):
		name := "GitHubStateError"
		if ce != nil {
			name = "GitHubConfigurationError"
		}
		s.audit().Security(ctx, slog.LevelWarn, "GITHUB_STATE_REJECTED", "ip", ip, "error", name)
		writeError(w, http.StatusBadRequest, msgInvalidLogin)
		return
	case errors.Is(err, errProvider):
		s.audit().Security(ctx, slog.LevelWarn, "GITHUB_PROVIDER_UNAVAILABLE", "ip", ip, "error", "GitHubProviderError")
		writeError(w, http.StatusServiceUnavailable, msgUnavailable)
		return
	default:
		s.fail(w, r, err)
		return
	}
	if f.Purpose == auth.PurposeLink {
		s.completeLink(w, r, f, p)
		return
	}
	s.completeLogin(w, r, f, p)
}

func (s *Service) callbackProfile(r *http.Request) (auth.Flight, Profile, error) {
	ctx := r.Context()
	cfg, secret, err := s.active(ctx)
	if err != nil {
		return auth.Flight{}, Profile{}, err
	}
	cb, err := auth.ParseCallback(r.URL.Query())
	if err != nil {
		return auth.Flight{}, Profile{}, errState
	}
	f, err := s.takeFlight(ctx, s.binding(r), cb.State, cfg.Generation)
	if err != nil {
		return auth.Flight{}, Profile{}, err
	}
	p, err := s.complete(ctx, cfg, secret, f, cb)
	return f, p, err
}

// completeLogin finds the account by the numeric GitHub id, provisions one
// where the policy allows it, and signs it in (_complete_login).
func (s *Service) completeLogin(w http.ResponseWriter, r *http.Request, f auth.Flight, p Profile) {
	ctx := r.Context()
	cfg, err := s.Configuration(ctx)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var userID int64
	err = s.DB.Write(ctx, func(tx *store.Tx) error {
		i, found, err := byGitHubTx(ctx, tx, p.UserID)
		if err != nil || !found {
			return err
		}
		userID = i.UserID
		return s.touchTx(ctx, tx, i.ID, p)
	})
	if err != nil {
		s.fail(w, r, fault.Wrap(fault.StorageError, err, ""))
		return
	}
	if userID == 0 {
		// Settings stored before the production rule existed fail closed too.
		if !cfg.AutoProvision || s.unrestricted(cfg.AutoProvision, cfg.AllowedOrgs) {
			s.audit().Security(ctx, slog.LevelWarn, "GITHUB_IDENTITY_REJECTED", "github_user_id", p.UserID, "reason", "unlinked")
			s.audit().Security(ctx, slog.LevelWarn, "GITHUB_LOGIN_FAILED", "github_user_id", p.UserID, "reason", "unlinked")
			writeError(w, http.StatusForbidden, msgNotLinked)
			return
		}
		i, err := s.provision(ctx, p)
		if fault.Is(err, fault.Conflict) {
			writeError(w, http.StatusConflict, msgProvision)
			return
		}
		if err != nil {
			s.fail(w, r, err)
			return
		}
		userID = i.UserID
		s.audit().Security(ctx, slog.LevelInfo, "GITHUB_ACCOUNT_PROVISIONED", "user", s.username(ctx, userID), "github_user_id", p.UserID)
	}
	acc, err := s.account(ctx, userID)
	if err != nil && !fault.Is(err, fault.NotFound) {
		s.fail(w, r, err)
		return
	}
	if err != nil || acc.Locked || acc.Managed == "ldap" {
		s.audit().Security(ctx, slog.LevelWarn, "GITHUB_LOGIN_FAILED", "github_user_id", p.UserID, "reason", "inactive_account")
		writeError(w, http.StatusForbidden, msgInactive)
		return
	}
	err = s.SignIn.SignInExternal(w, r, userID, "github", f.Continuation)
	if fault.Is(err, fault.Forbidden) {
		writeError(w, http.StatusForbidden, msgNoLocalMFA)
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.audit().Security(ctx, slog.LevelInfo, "GITHUB_LOGIN_SUCCESS", "user", acc.Username, "github_user_id", p.UserID)
}

func (s *Service) account(ctx context.Context, userID int64) (Account, error) {
	var acc Account
	err := s.DB.Read(ctx, func(tx *store.Tx) error {
		var err error
		acc, err = s.Accounts.AccountTx(ctx, tx, userID)
		return err
	})
	if err != nil && !fault.Is(err, fault.NotFound) {
		return Account{}, fault.Wrap(fault.StorageError, err, "")
	}
	return acc, err
}

func (s *Service) username(ctx context.Context, userID int64) string {
	acc, err := s.account(ctx, userID)
	if err != nil {
		return ""
	}
	return acc.Username
}

// completeLink binds the identity to the signed-in account that started
// the flight, in the same browser session and authentication generation
// (_complete_link).
func (s *Service) completeLink(w http.ResponseWriter, r *http.Request, f auth.Flight, p Profile) {
	ctx := r.Context()
	pr, ok := principal.From(ctx)
	if !ok || pr.UserID != f.UserID || pr.SessionID != f.SessionID {
		writeError(w, http.StatusForbidden, msgLinkFailed)
		return
	}
	var collision bool
	err := s.DB.Write(ctx, func(tx *store.Tx) error {
		acc, err := s.Accounts.AccountTx(ctx, tx, pr.UserID)
		if err != nil {
			return err
		}
		if acc.Locked || acc.Generation != f.Generation {
			return fault.New(fault.Forbidden, msgLinkFailed)
		}
		if acc.Managed == "ldap" {
			return fault.New(fault.Conflict, "GitHub cannot be linked to this account")
		}
		_, err = insertTx(ctx, tx, s.newIdentity(pr.UserID, p, false))
		collision = errors.Is(err, errIdentityLinked)
		return err
	})
	switch {
	case collision:
		s.audit().Security(ctx, slog.LevelWarn, "GITHUB_IDENTITY_COLLISION", "user", pr.Username, "github_user_id", p.UserID)
		writeError(w, http.StatusConflict, msgAlreadyLinked)
		return
	case fault.Is(err, fault.NotFound):
		writeError(w, http.StatusForbidden, msgLinkFailed)
		return
	case err != nil:
		if fe, ok := fault.From(err); ok && (fe.Code == fault.Forbidden || fe.Code == fault.Conflict) {
			status, _, _ := fault.Status(err)
			writeError(w, status, fe.Message)
			return
		}
		s.fail(w, r, fault.Wrap(fault.StorageError, err, ""))
		return
	}
	s.audit().Security(ctx, slog.LevelInfo, "GITHUB_IDENTITY_LINKED", "user", pr.Username, "github_user_id", p.UserID)
	http.Redirect(w, r, auth.PublicContinuation(s.Root, f.Continuation), http.StatusFound)
}
