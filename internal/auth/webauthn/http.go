package webauthn

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

// DirectSignIn opens a browser session for a sign-in without a password
// (provided by auth.Flow.SignInDirect).
type DirectSignIn interface {
	SignInDirect(w http.ResponseWriter, r *http.Request, userID int64, method string, assurance auth.Assurance) error
}

// HTTP serves the passkey routes. The edge mounts it behind session, CSRF
// and origin checks; the sign-in routes have no session yet and rely on
// the browser binding and the pending sign-in instead. Every route
// answers 404 while the passkey feature is off.
type HTTP struct {
	Service *Service
	Gates   auth.Gates
	StepUp  StepUp
	Pending auth.PendingSignIn
	SignIn  DirectSignIn
	// Binding returns the browser binding the HTTP edge keeps
	// (httpapi.BrowserBinding); sign-in challenges are tied to it.
	Binding func(*http.Request) string
	Limits  auth.FactorLimits
	Audit   auth.Audit
	Logger  *slog.Logger
}

// Register adds the routes to mux, relative to APPLICATION_ROOT.
func (h *HTTP) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/webauthn/credentials", h.gated(h.list))
	mux.HandleFunc("DELETE /api/webauthn/credentials/{id}", h.gated(h.delete))
	mux.HandleFunc("POST /api/webauthn/mfa", h.gated(h.enableMFA))
	mux.HandleFunc("POST /api/webauthn/register/options", h.gated(h.registrationOptions))
	mux.HandleFunc("POST /api/webauthn/register/verify", h.gated(h.verifyRegistration))
	mux.HandleFunc("POST /api/webauthn/auth/options", h.gated(h.signInOptions))
	mux.HandleFunc("POST /api/webauthn/auth/verify", h.gated(h.signIn))
}

func (h *HTTP) audit() auth.Audit { return auth.AuditOrLog(h.Audit, h.Logger) }

func (h *HTTP) fail(w http.ResponseWriter, r *http.Request, err error) {
	auth.WriteError(w, r, h.Logger, err)
}

func (h *HTTP) gated(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		on, err := false, error(nil)
		if h.Gates != nil {
			on, err = h.Gates.Active(r.Context(), auth.FeaturePasskey)
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

type credentialJSONOut struct {
	ID         int64   `json:"id"`
	Name       string  `json:"name"`
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
	rows, err := h.Service.List(ctx, p.UserID)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	out := make([]credentialJSONOut, 0, len(rows))
	for _, c := range rows {
		j := credentialJSONOut{ID: c.ID, Name: c.Name, CreatedAt: isoformat(c.CreatedAt)}
		if !c.LastUsedAt.IsZero() {
			used := isoformat(c.LastUsedAt)
			j.LastUsedAt = &used
		}
		out = append(out, j)
	}
	auth.WriteJSON(w, http.StatusOK, map[string]any{"credentials": out})
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
	if err := h.StepUp.Consume(ctx, p, principal.ActionPasskeyDelete, raw, r.Header.Get(auth.StepUpHeader)); err != nil {
		h.fail(w, r, auth.ErrStepUp)
		return
	}
	if err := h.Service.Delete(ctx, p, id); err != nil {
		h.fail(w, r, err)
		return
	}
	h.audit().Security(ctx, slog.LevelInfo, "WEBAUTHN_CREDENTIAL_DELETED", "user", p.Username)
	auth.WriteJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (h *HTTP) enableMFA(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := principal.Require(ctx)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	if !auth.ReadObject(w, r).True("confirm_enable_mfa") {
		h.fail(w, r, fault.New(fault.InvalidRequest, "MFA activation must be confirmed"))
		return
	}
	if err := h.StepUp.Consume(ctx, p, principal.ActionMFAEnable, strconv.FormatInt(p.UserID, 10), r.Header.Get(auth.StepUpHeader)); err != nil {
		h.fail(w, r, auth.ErrStepUp)
		return
	}
	codes, err := h.Service.EnableMFA(ctx, p)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.audit().Security(ctx, slog.LevelInfo, "MFA_ENABLED", "user", p.Username, "factor", "passkey")
	auth.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "recovery_codes": codes})
}

func (h *HTTP) registrationOptions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := principal.RequireAllowingRecovery(ctx)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	body := auth.ReadObject(w, r)
	// A recovery session may repair its factors without a grant.
	if !p.Recovery {
		if err := h.StepUp.Consume(ctx, p, principal.ActionPasskeyEnroll, strconv.FormatInt(p.UserID, 10), r.Header.Get(auth.StepUpHeader)); err != nil {
			h.fail(w, r, auth.ErrStepUp)
			return
		}
	}
	options, err := h.Service.BeginRegistration(ctx, p, body.True("legacy_upgrade"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	auth.WriteJSON(w, http.StatusOK, options)
}

func (h *HTTP) verifyRegistration(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := principal.RequireAllowingRecovery(ctx)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	body := auth.ReadObject(w, r)
	ceremony, _ := body.String("ceremony")
	name, _ := body.String("name")
	id, err := h.Service.FinishRegistration(ctx, p, ceremony, body["credential"], name)
	if err != nil {
		if fault.Is(err, fault.InvalidRequest) {
			h.audit().Security(ctx, slog.LevelWarn, "WEBAUTHN_REGISTRATION_REJECTED", "user", p.Username, "reason", Reason(err))
			err = errRegistration
		} else if fault.Is(err, fault.Unavailable) {
			h.audit().Security(ctx, slog.LevelError, "WEBAUTHN_CREDENTIAL_STORAGE_FAILED", "user", p.Username)
		}
		h.fail(w, r, err)
		return
	}
	h.audit().Security(ctx, slog.LevelInfo, "WEBAUTHN_CREDENTIAL_REGISTERED", "user", p.Username)
	auth.WriteJSON(w, http.StatusCreated, map[string]any{"id": id, "name": NormalizeName(name)})
}
