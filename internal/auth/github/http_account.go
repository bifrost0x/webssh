package github

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/bifrost0x/webssh/internal/auth"
	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/store"
)

// Texts of the account routes.
const (
	msgLDAPManaged     = "GitHub cannot be linked to an LDAP-managed account"
	msgHasIdentity     = "A GitHub identity is already linked"
	msgNoIdentity      = "No GitHub identity is linked"
	msgNeedPasskey     = "Add and test a passkey before disconnecting GitHub" // #nosec G101 -- a message, not a credential
	msgSignInAgain     = "Sign in again before disconnecting GitHub"
	msgStorage         = "GitHub identity storage is temporarily unavailable"
	msgAdminConversion = "This account is listed in ADMIN_USERS. Remove it from ADMIN_USERS before converting it to a local account."
)

// linkStart is POST /api/account/github/link/start: after the github.link
// step-up it starts a redirect that binds a GitHub identity to the
// signed-in account, in this session and generation.
func (s *Service) linkStart(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := principal.Require(ctx)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !s.consume(w, r, p, principal.ActionGitHubLink, itoa(p.UserID)) {
		return
	}
	if !s.Active(ctx) {
		http.NotFound(w, r)
		return
	}
	acc, err := s.account(ctx, p.UserID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if acc.Managed == "ldap" {
		writeError(w, http.StatusConflict, msgLDAPManaged)
		return
	}
	if _, found, err := s.Identity(ctx, p.UserID); err != nil {
		s.fail(w, r, err)
		return
	} else if found {
		writeError(w, http.StatusConflict, msgHasIdentity)
		return
	}
	f := auth.NewFlight(auth.ProviderGitHub, auth.PurposeLink, s.now())
	f.Nonce, f.Continuation = "", "/security"
	f.UserID, f.Generation, f.SessionID = p.UserID, acc.Generation, p.SessionID
	u, err := s.begin(r, f)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	auth.WriteJSON(w, http.StatusOK, map[string]string{"authorization_url": u})
}

type identityJSON struct {
	CreatedAt    string  `json:"created_at"`
	DisplayName  *string `json:"display_name"`
	GitHubUserID string  `json:"github_user_id"`
	ID           int64   `json:"id"`
	Login        string  `json:"login"`
}

// pyISO renders t like Python's naive datetime.isoformat() in UTC.
func pyISO(t time.Time) string {
	t = t.UTC()
	if t.Nanosecond()/1000 == 0 {
		return t.Format("2006-01-02T15:04:05")
	}
	return t.Format("2006-01-02T15:04:05.000000")
}

// status is GET /api/account/github.
func (s *Service) status(w http.ResponseWriter, r *http.Request) {
	p, err := principal.Require(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	i, found, err := s.Identity(r.Context(), p.UserID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !found {
		auth.WriteJSON(w, http.StatusOK, map[string]any{"identity": nil})
		return
	}
	out := identityJSON{ID: i.ID, GitHubUserID: i.GitHubUserID, Login: i.Login, CreatedAt: pyISO(i.CreatedAt)}
	if i.HasName {
		out.DisplayName = &i.DisplayName
	}
	auth.WriteJSON(w, http.StatusOK, map[string]any{"identity": out})
}

var errNeedPasskey = fault.New(fault.Conflict, msgNeedPasskey)

func (s *Service) passkeys(ctx context.Context, tx *store.Tx, userID int64) (int, error) {
	if s.Passkeys == nil {
		return 0, nil
	}
	return s.Passkeys.Count(ctx, tx, userID)
}

// unlink is DELETE /api/account/github: after the github.unlink step-up
// it removes the account's GitHub identity. An account GitHub created
// needs a passkey first, its only remaining primary sign-in, and may not
// be listed in ADMIN_USERS. Every other browser of the account is signed
// out; this one continues in a new session.
func (s *Service) unlink(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := principal.Require(ctx)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !s.consume(w, r, p, principal.ActionGitHubUnlink, itoa(p.UserID)) {
		return
	}
	i, found, err := s.Identity(ctx, p.UserID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, msgNoIdentity)
		return
	}
	s.audit().Security(ctx, slog.LevelInfo, "GITHUB_IDENTITY_UNLINK_ATTEMPTED", "user", p.Username, "github_user_id", i.GitHubUserID)
	if i.Provisioned && s.Admins != nil && s.Admins.Reserves(p.Username) {
		s.audit().Security(ctx, slog.LevelWarn, "GITHUB_IDENTITY_UNLINK_REJECTED", "user", p.Username,
			"github_user_id", i.GitHubUserID, "reason", "listed_in_admin_users")
		writeError(w, http.StatusConflict, msgAdminConversion)
		return
	}
	change := func(ctx context.Context, tx *store.Tx) error {
		if i.Provisioned {
			n, err := s.passkeys(ctx, tx, p.UserID)
			if err != nil {
				return err
			}
			if n == 0 {
				return errNeedPasskey
			}
		}
		res, err := tx.ExecContext(ctx, `DELETE FROM authgithub_identities WHERE id = ? AND user_id = ?`, i.ID, p.UserID)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return fault.New(fault.NotFound, msgNoIdentity)
		}
		if i.Provisioned {
			return s.Accounts.ReleaseTx(ctx, tx, p.UserID, "")
		}
		return nil
	}
	// The owner acted, so persistent tmux sessions stay as on sign-out;
	// the connections of every browser still close.
	err = s.SignIn.RenewAfter(w, r, principal.ReasonLogout, change)
	switch {
	case errors.Is(err, errNeedPasskey):
		writeError(w, http.StatusConflict, msgNeedPasskey)
		return
	case fault.Is(err, fault.NotFound):
		writeError(w, http.StatusNotFound, msgNoIdentity)
		return
	case fault.Is(err, fault.AuthenticationNeeded):
		writeError(w, http.StatusConflict, msgSignInAgain)
		return
	case err != nil:
		s.audit().Security(ctx, slog.LevelError, "GITHUB_IDENTITY_STORAGE_FAILED", "user", p.Username, "error", string(fault.CodeOf(err)))
		writeError(w, http.StatusServiceUnavailable, msgStorage)
		return
	}
	s.audit().Security(ctx, slog.LevelWarn, "GITHUB_IDENTITY_UNLINKED", "user", p.Username, "github_user_id", i.GitHubUserID)
	auth.WriteJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
