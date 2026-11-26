package totp

import (
	"context"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/bifrost0x/webssh/internal/auth"
	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
)

// StepUp consumes a step-up grant for one action on one target (provided
// by internal/auth/stepup). It fails with fault.StepUpRequired when the
// grant is missing, expired, already used or bound to another user,
// session, action or target; the caller then refuses the operation.
type StepUp interface {
	Consume(ctx context.Context, p principal.Principal, action principal.Action, target, grant string) error
}

// HTTP serves the TOTP routes. The edge mounts it behind session, CSRF and
// origin checks; the sign-in route relies on the pending sign-in instead
// of a session. Every route answers 404 while the totp feature is off.
type HTTP struct {
	Service *Service
	Gates   auth.Gates
	StepUp  StepUp
	Pending auth.PendingSignIn
	Limits  auth.Limits
	Audit   auth.Audit
	Logger  *slog.Logger
}

// Register adds the routes to mux, relative to APPLICATION_ROOT.
func (h *HTTP) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/totp/authenticators", h.gated(h.list))
	mux.HandleFunc("DELETE /api/totp/authenticators/{id}", h.gated(h.delete))
	mux.HandleFunc("POST /api/totp/enroll", h.gated(h.enroll))
	mux.HandleFunc("POST /api/totp/enroll/verify", h.gated(h.verifyEnrollment))
	mux.HandleFunc("POST /api/totp/auth/verify", h.gated(h.signIn))
}

func (h *HTTP) audit() auth.Audit { return auth.AuditOrLog(h.Audit, h.Logger) }

func (h *HTTP) fail(w http.ResponseWriter, r *http.Request, err error) {
	auth.WriteError(w, r, h.Logger, err)
}

func (h *HTTP) gated(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		on, err := false, error(nil)
		if h.Gates != nil {
			on, err = h.Gates.Active(r.Context(), auth.FeatureTOTP)
		}
		switch {
		case err != nil:
			h.fail(w, r, err)
		case !on:
			h.fail(w, r, fault.New(fault.NotFound, ""))
		default:
			next(w, r)
		}
	}
}

type authenticatorJSON struct {
	ID         int64   `json:"id"`
	Label      string  `json:"label"`
	CreatedAt  string  `json:"created_at"`
	LastUsedAt *string `json:"last_used_at"`
}

func (h *HTTP) list(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := principal.RequireAllowingRecovery(ctx)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	state, err := h.Service.MFA.State(ctx, p.UserID)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	rows, err := h.Service.List(ctx, p.UserID)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	out := make([]authenticatorJSON, 0, len(rows))
	for _, a := range rows {
		j := authenticatorJSON{ID: a.ID, Label: a.Label, CreatedAt: isoformat(a.CreatedAt)}
		if !a.LastUsedAt.IsZero() {
			used := isoformat(a.LastUsedAt)
			j.LastUsedAt = &used
		}
		out = append(out, j)
	}
	auth.WriteJSON(w, http.StatusOK, map[string]any{"mfa_enabled": state.MFAEnabled, "authenticators": out})
}

func (h *HTTP) delete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := principal.Require(ctx)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	raw := r.PathValue("id")
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || id <= 0 || strconv.FormatInt(id, 10) != raw {
		h.fail(w, r, errNotFound)
		return
	}
	owned, err := h.Service.Owned(ctx, p.UserID, id)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	if !owned {
		h.fail(w, r, errNotFound)
		return
	}
	if err := h.StepUp.Consume(ctx, p, principal.ActionTOTPDelete, raw, r.Header.Get(auth.StepUpHeader)); err != nil {
		h.fail(w, r, auth.ErrStepUp)
		return
	}
	mfaOn, err := h.Service.Delete(ctx, p, id)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.audit().Security(ctx, slog.LevelInfo, "TOTP_AUTHENTICATOR_DELETED", "user", p.Username, "authenticator_id", id)
	auth.WriteJSON(w, http.StatusOK, map[string]bool{"ok": true, "mfa_enabled": mfaOn})
}

func (h *HTTP) enroll(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := principal.RequireAllowingRecovery(ctx)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	body := auth.ReadObject(w, r)
	// A recovery session may repair its factors without a grant.
	if !p.Recovery {
		if err := h.StepUp.Consume(ctx, p, principal.ActionTOTPEnroll, strconv.FormatInt(p.UserID, 10), r.Header.Get(auth.StepUpHeader)); err != nil {
			h.fail(w, r, auth.ErrStepUp)
			return
		}
	}
	raw, present := body.String("label")
	label, ok := NormalizeLabel(raw, present)
	if !ok {
		h.fail(w, r, errLabel)
		return
	}
	e, err := h.Service.Begin(ctx, p, label)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.audit().Security(ctx, slog.LevelInfo, "TOTP_ENROLLMENT_STARTED", "user", p.Username)
	auth.WriteJSON(w, http.StatusOK, map[string]string{
		"token":            e.Token,
		"secret":           e.Secret,
		"provisioning_uri": e.ProvisioningURI,
		"qr_svg":           e.QRSVG,
		"expires_at":       isoformat(e.ExpiresAt),
	})
}

func (h *HTTP) verifyEnrollment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := principal.RequireAllowingRecovery(ctx)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	if h.Limits.ReauthLimited(r, p.UserID, "totp_enrollment_verify") {
		h.fail(w, r, auth.TooManyAttempts())
		return
	}
	body := auth.ReadObject(w, r)
	if !body.True("confirm_enable_mfa") {
		h.fail(w, r, fault.New(fault.InvalidRequest, "MFA activation must be confirmed"))
		return
	}
	token, _ := body.String("token")
	code, _ := body.String("code")
	a, err := h.Service.Activate(ctx, p, token, code)
	if err != nil {
		if fault.Is(err, fault.InvalidRequest) {
			h.audit().Security(ctx, slog.LevelWarn, "TOTP_ENROLLMENT_REJECTED", "user", p.Username)
		}
		h.fail(w, r, err)
		return
	}
	h.audit().Security(ctx, slog.LevelInfo, "MFA_ENABLED", "user", p.Username, "factor", "totp")
	codes := a.RecoveryCodes
	if codes == nil {
		codes = []string{}
	}
	auth.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "authenticator_id": a.AuthenticatorID, "recovery_codes": codes})
}

var errRestart = fault.New(fault.MFARestart, "Too many invalid codes. Sign in again.")

// signIn completes a pending sign-in with a TOTP code.
func (h *HTTP) signIn(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if h.Limits.SourceLimited(r, "totp_login") {
		h.fail(w, r, auth.TooManyAttempts())
		return
	}
	pending, err := h.Pending.Pending(r)
	if err != nil {
		h.fail(w, r, auth.PendingInvalid())
		return
	}
	if h.Limits.UserLimited(r, pending.UserID, "totp_login_account", h.Limits.Login) {
		h.fail(w, r, auth.TooManyAttempts())
		return
	}
	code, _ := auth.ReadObject(w, r).String("code")
	err = h.Service.CheckCode(ctx, pending.UserID, code, auth.ScopeLogin)
	switch {
	case fault.Is(err, fault.AuthFailed):
		failures := Failures(err)
		h.audit().Security(ctx, slog.LevelWarn, "TOTP_AUTHENTICATION_REJECTED", "user_id", pending.UserID, "failures", failures)
		if auth.PendingShouldBeDiscarded(failures) {
			if derr := h.Pending.Discard(w, r); derr != nil {
				h.fail(w, r, derr)
				return
			}
			h.audit().Security(ctx, slog.LevelWarn, "MFA_PENDING_LOGIN_DISCARDED", "user_id", pending.UserID, "method", "totp", "failures", failures)
			h.fail(w, r, errRestart)
			return
		}
		// The page matches this text; the code stays a 401 like Python's.
		h.fail(w, r, fault.New(fault.AuthenticationNeeded, "TOTP code is invalid"))
		return
	case fault.Is(err, fault.RateLimited):
		h.audit().Security(ctx, slog.LevelWarn, "MFA_ATTEMPT_THROTTLED", "user_id", pending.UserID, "method", "totp", "flow", "login")
		h.fail(w, r, err)
		return
	case err != nil:
		h.fail(w, r, err)
		return
	}
	continuation, err := h.Pending.Complete(w, r, pending.UserID, "totp", auth.AssuranceMFA)
	if err != nil {
		h.fail(w, r, auth.PendingInvalid())
		return
	}
	auth.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "continuation": continuation})
}
