package auth

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/store"
)

// StepUpHeader carries the step-up grant of a request.
const StepUpHeader = "X-WebSSH-Step-Up"

// StepUp consumes a step-up grant for one action on one target (provided
// by internal/auth/stepup). It fails with fault.StepUpRequired when the
// grant is missing, expired, already used or bound to another user,
// session, action or target; the caller then refuses the operation.
type StepUp interface {
	Consume(ctx context.Context, p principal.Principal, action principal.Action, target, grant string) error
}

// FactorHTTP serves the account-wide factor routes: security state, the
// one MFA switch-off (two entry points), recovery code rotation and the
// recovery sign-in. The edge mounts it behind session, CSRF and origin
// checks and puts the principal into the context; the recovery sign-in
// has no session yet and relies on the pending sign-in instead.
type FactorHTTP struct {
	MFA      *MFA
	Recovery *Recovery
	Throttle *Throttle
	StepUp   StepUp
	Pending  PendingSignIn
	Limits   Limits
	// Root is APPLICATION_ROOT without the trailing slash.
	Root   string
	Audit  Audit
	Logger *slog.Logger
}

// Register adds the routes to mux, relative to APPLICATION_ROOT.
func (h *FactorHTTP) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/account/security-state", h.securityState)
	mux.HandleFunc("POST /api/account/mfa/disable", h.disableMFA)
	mux.HandleFunc("POST /api/auth/mfa/disable", h.disableMFAAfterRecovery)
	mux.HandleFunc("POST /api/recovery-codes", h.rotateRecoveryCodes)
	mux.HandleFunc("POST /api/auth/recovery", h.recoverySignIn)
}

func (h *FactorHTTP) logger() *slog.Logger {
	if h.Logger != nil {
		return h.Logger
	}
	return slog.Default()
}

func (h *FactorHTTP) audit() Audit { return AuditOrLog(h.Audit, h.Logger) }

func (h *FactorHTTP) fail(w http.ResponseWriter, r *http.Request, err error) {
	WriteError(w, r, h.Logger, err)
}

// featureOn answers 404 when feature is off, like the Python routes.
func (h *FactorHTTP) featureOn(w http.ResponseWriter, r *http.Request, feature string) bool {
	on, err := h.MFA.active(r.Context(), feature)
	if err != nil {
		h.fail(w, r, err)
		return false
	}
	if !on {
		h.fail(w, r, fault.New(fault.NotFound, ""))
	}
	return on
}

func (h *FactorHTTP) securityState(w http.ResponseWriter, r *http.Request) {
	p, err := principal.RequireAllowingRecovery(r.Context())
	if err != nil {
		h.fail(w, r, err)
		return
	}
	state, err := h.MFA.State(r.Context(), p.UserID)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	WriteJSON(w, http.StatusOK, state)
}

func (h *FactorHTTP) disableMFA(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := principal.Require(ctx)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	if !ReadObject(w, r).True("confirm_disable_mfa") {
		h.fail(w, r, fault.New(fault.InvalidRequest, "MFA deactivation must be confirmed"))
		return
	}
	state, err := h.MFA.State(ctx, p.UserID)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	if !state.MFAEnabled {
		h.fail(w, r, errStateChanged)
		return
	}
	if err := h.StepUp.Consume(ctx, p, principal.ActionMFADisable, itoa(p.UserID), r.Header.Get(StepUpHeader)); err != nil {
		h.fail(w, r, stepUpError(err))
		return
	}
	if err := h.MFA.Disable(ctx, p); err != nil {
		h.fail(w, r, err)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (h *FactorHTTP) disableMFAAfterRecovery(w http.ResponseWriter, r *http.Request) {
	if !h.featureOn(w, r, FeatureRecovery) {
		return
	}
	p, err := principal.RequireAllowingRecovery(r.Context())
	if err != nil {
		h.fail(w, r, err)
		return
	}
	if !p.Recovery {
		h.fail(w, r, fault.New(fault.Forbidden, "Recovery session is required"))
		return
	}
	if name, ok := ReadObject(w, r).String("confirm_username"); !ok || name != p.Username {
		h.fail(w, r, fault.New(fault.InvalidRequest, "Account confirmation does not match"))
		return
	}
	if err := h.MFA.Disable(r.Context(), p); err != nil {
		h.fail(w, r, err)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (h *FactorHTTP) rotateRecoveryCodes(w http.ResponseWriter, r *http.Request) {
	if !h.featureOn(w, r, FeatureRecovery) {
		return
	}
	ctx := r.Context()
	p, err := principal.Require(ctx)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	if err := h.StepUp.Consume(ctx, p, principal.ActionRecoveryRotate, itoa(p.UserID), r.Header.Get(StepUpHeader)); err != nil {
		h.fail(w, r, stepUpError(err))
		return
	}
	codes, err := h.Recovery.Generate(ctx, p.UserID)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.audit().Security(ctx, slog.LevelInfo, "RECOVERY_CODES_REGENERATED", "user", p.Username)
	WriteJSON(w, http.StatusOK, map[string][]string{"codes": codes})
}

var (
	errTooManyAttempts = fault.New(fault.RateLimited, "Too many authentication attempts")
	errRecoveryFailed  = fault.New(fault.AuthenticationNeeded, "Recovery authentication failed")
	errPendingInvalid  = fault.New(fault.AuthenticationNeeded, "Pending authentication is invalid")
)

// TooManyAttempts is the answer of a sign-in route over its rate limit.
func TooManyAttempts() error { return errTooManyAttempts }

// PendingInvalid is the answer when the pending sign-in is gone.
func PendingInvalid() error { return errPendingInvalid }

// recoverySignIn completes a pending password sign-in with a recovery code
// and opens a recovery session that may only repair second factors.
func (h *FactorHTTP) recoverySignIn(w http.ResponseWriter, r *http.Request) {
	if !h.featureOn(w, r, FeatureRecovery) {
		return
	}
	ctx := r.Context()
	if h.Limits.SourceLimited(r, "recovery_mfa") {
		h.fail(w, r, errTooManyAttempts)
		return
	}
	pending, err := h.Pending.Pending(r)
	if err != nil {
		h.fail(w, r, errPendingInvalid)
		return
	}
	if pending.PrimaryMethod != "password" && pending.PrimaryMethod != "ldap" {
		h.fail(w, r, errRecoveryFailed)
		return
	}
	if h.Limits.UserLimited(r, pending.UserID, "recovery_mfa_account", h.Limits.Login) {
		h.fail(w, r, errTooManyAttempts)
		return
	}
	code, _ := ReadObject(w, r).String("code")
	var required bool
	if err := h.MFA.DB.Read(ctx, func(tx *store.Tx) error {
		var err error
		required, err = h.MFA.Accounts.MFARequired(ctx, tx, pending.UserID)
		return err
	}); err != nil {
		h.fail(w, r, err)
		return
	}
	if !required {
		h.fail(w, r, errRecoveryFailed)
		return
	}
	ok, err := h.Recovery.Consume(ctx, pending.UserID, code)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	if !ok {
		h.audit().Security(ctx, slog.LevelWarn, "RECOVERY_AUTHENTICATION_REJECTED", "user_id", pending.UserID)
		h.fail(w, r, errRecoveryFailed)
		return
	}
	if _, err := h.Pending.Complete(w, r, pending.UserID, "recovery_code", AssuranceMFA); err != nil {
		h.fail(w, r, errRecoveryFailed)
		return
	}
	if err := h.Throttle.ResetAll(ctx, pending.UserID); err != nil {
		h.logger().ErrorContext(ctx, "code backoff not cleared after recovery sign-in", "error", err)
	}
	h.audit().Security(ctx, slog.LevelInfo, "RECOVERY_RESTRICTED_SESSION_STARTED", "user_id", pending.UserID)
	WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "recovery_required": true, "continuation": h.Root + "/security"})
}
