package oidc

import (
	"errors"
	"net/http"

	"github.com/bifrost0x/webssh/internal/auth"
	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/store"
)

// methodOIDC is the authentication and step-up method name.
const methodOIDC = "oidc"

// callback is the provider's redirect back (auth.PathOIDCCallback). The
// flight is taken first, so a second callback with the same state finds
// nothing; the bindings of link and step-up are checked before the code
// is redeemed.
func (h *HTTP) callback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if h.Limits.SourceLimited(r, "oidc_callback") {
		errorJSON(w, http.StatusTooManyRequests, msgTooMany)
		return
	}
	cb, err := auth.ParseCallback(r.URL.Query())
	if err != nil {
		h.rejectState(w, r, "malformed_callback")
		return
	}
	f, err := h.Flights.Take(h.Binding(r), cb.State)
	if err != nil {
		h.rejectState(w, r, "unknown_state")
		return
	}
	p, signedIn := principalOf(r)
	switch f.Purpose {
	case auth.PurposeLink:
		if !signedIn || p.UserID != f.UserID || p.SessionID != f.SessionID || !h.linkable(r, f) {
			h.audit("OIDC_IDENTITY_LINK_REJECTED", "reason", "account_binding_mismatch")
			errorJSON(w, http.StatusForbidden, msgLinkFailed)
			return
		}
	case auth.PurposeStepUp:
		if !signedIn || p.UserID != f.UserID || p.SessionID != f.SessionID || (f.Action != "" && !p.IsAdmin) {
			errorJSON(w, http.StatusForbidden, msgStepUpFailed)
			return
		}
	}
	res, err := h.Provider.complete(ctx, f, cb)
	if err != nil {
		h.logger().WarnContext(ctx, "OIDC callback rejected", "error", err)
		if fault.Is(err, fault.Unavailable) {
			errorJSON(w, http.StatusServiceUnavailable, msgUnavailable)
			return
		}
		h.rejectState(w, r, "token_rejected")
		return
	}
	id := res.identity
	if f.Purpose == auth.PurposeLink {
		h.completeLink(w, r, p, f, id)
		return
	}
	acc, ok := h.resolve(w, r, id)
	if !ok {
		return
	}
	h.audit("OIDC_ASSURANCE_EVALUATED", "user", acc.Username, "assurance", string(res.assessment.Level),
		"reason", res.assessment.Reason, "auth_time_present", !res.assessment.AuthTime.IsZero())
	if f.Purpose == auth.PurposeStepUp {
		h.completeStepUp(w, r, p, f, acc, res.assessment)
		return
	}
	err = h.SignIn.SignInExternal(w, r, auth.ExternalSignIn{UserID: acc.ID, Method: methodOIDC,
		Assurance: res.assessment.Level, StrongAt: res.assessment.AuthTime, Continuation: f.Continuation})
	if err != nil {
		if fe, ok := fault.From(err); ok && fe.Code == fault.Forbidden && fe.Message != "" {
			h.audit("OIDC_LOCAL_MFA_UNAVAILABLE", "user", acc.Username)
			errorJSON(w, http.StatusForbidden, fe.Message)
			return
		}
		h.logger().WarnContext(ctx, "OIDC sign-in not finished", "error", err)
		errorJSON(w, http.StatusForbidden, msgNotLinked)
		return
	}
	h.audit("OIDC_LOGIN_SUCCESS", "user", acc.Username, "issuer", id.Issuer, "assurance", string(res.assessment.Level))
}

func (h *HTTP) rejectState(w http.ResponseWriter, r *http.Request, reason string) {
	h.audit("OIDC_STATE_REJECTED", "reason", reason)
	h.logger().InfoContext(r.Context(), "OIDC callback refused", "reason", reason)
	errorJSON(w, http.StatusBadRequest, msgInvalidLogin)
}

// resolve finds the account of a sign-in or step-up identity: linked,
// not locked and not managed by LDAP (oidc_routes.py).
func (h *HTTP) resolve(w http.ResponseWriter, r *http.Request, id auth.Identity) (Account, bool) {
	ctx := r.Context()
	reason := ""
	var acc Account
	userID, err := h.Links.Account(ctx, id)
	switch {
	case fault.Is(err, fault.NotFound):
		reason = "unlinked"
	case err != nil:
		h.logger().ErrorContext(ctx, "OIDC identity lookup failed", "error", err)
		errorJSON(w, http.StatusServiceUnavailable, msgUnavailable)
		return Account{}, false
	default:
		acc, err = h.Accounts.OIDCAccount(ctx, userID)
		switch {
		case err != nil:
			reason = "unlinked"
		case acc.Locked:
			reason = "account_locked"
		case acc.Managed == "ldap":
			reason = "externally_managed"
		}
	}
	if reason != "" {
		h.audit("OIDC_IDENTITY_REJECTED", "issuer", id.Issuer, "reason", reason)
		errorJSON(w, http.StatusForbidden, msgNotLinked)
		return Account{}, false
	}
	return acc, true
}

// linkable checks that the account that started a link is unchanged:
// not locked and still at the auth generation of the start.
func (h *HTTP) linkable(r *http.Request, f auth.Flight) bool {
	acc, err := h.Accounts.OIDCAccount(r.Context(), f.UserID)
	return err == nil && !acc.Locked && acc.Generation == f.Generation
}

// errAccountChanged marks a link whose account changed after the check.
var errAccountChanged = errors.New("oidc: account changed during the link")

// completeLink binds the identity to the signed-in account
// (_complete_oidc_self_link). An identity already on this account is
// confirmed; one on another account is a conflict and never moves.
func (h *HTTP) completeLink(w http.ResponseWriter, r *http.Request, p principal.Principal, f auth.Flight, id auth.Identity) {
	ctx := r.Context()
	acc, err := h.Accounts.OIDCAccount(ctx, p.UserID)
	if err != nil || acc.Locked || acc.Generation != f.Generation {
		h.audit("OIDC_IDENTITY_LINK_REJECTED", "issuer", id.Issuer, "reason", "account_session_changed")
		errorJSON(w, http.StatusForbidden, msgLinkFailed)
		return
	}
	if acc.Managed != "" {
		errorJSON(w, http.StatusConflict, msgLinkRefused)
		return
	}
	owner, err := h.Links.Account(ctx, id)
	switch {
	case err == nil && owner == p.UserID:
		h.audit("OIDC_IDENTITY_LINK_CONFIRMED", "user", acc.Username, "issuer", id.Issuer)
		http.Redirect(w, r, auth.PublicContinuation(h.Root, f.Continuation), http.StatusFound)
		return
	case err == nil:
		h.audit("OIDC_IDENTITY_LINK_COLLISION", "user", acc.Username, "issuer", id.Issuer)
		errorJSON(w, http.StatusConflict, msgLinked)
		return
	case !fault.Is(err, fault.NotFound):
		h.logger().ErrorContext(ctx, "OIDC identity lookup failed", "error", err)
		errorJSON(w, http.StatusServiceUnavailable, msgStorage)
		return
	}
	err = h.Links.DB.Write(ctx, func(tx *store.Tx) error {
		// The account is checked again in the transaction that links, so
		// a lock, a generation raise or a conversion to a managed account
		// that commits meanwhile is not overtaken (the INSERT … SELECT of
		// the Python release).
		cur, err := h.Accounts.OIDCAccountTx(ctx, tx, p.UserID)
		if err != nil || cur.Locked || cur.Generation != f.Generation || cur.Managed != "" {
			return errors.Join(errAccountChanged, err)
		}
		_, err = h.Links.LinkTx(ctx, tx, p.UserID, id)
		return err
	})
	if err != nil {
		if errors.Is(err, errAccountChanged) {
			h.audit("OIDC_IDENTITY_LINK_REJECTED", "issuer", id.Issuer, "reason", "account_session_changed")
			errorJSON(w, http.StatusForbidden, msgLinkFailed)
			return
		}
		if fault.Is(err, fault.Conflict) {
			errorJSON(w, http.StatusConflict, msgLinked)
			return
		}
		h.audit("OIDC_IDENTITY_STORAGE_FAILED", "user", acc.Username, "issuer", id.Issuer)
		h.logger().ErrorContext(ctx, "OIDC identity not stored", "error", err)
		errorJSON(w, http.StatusServiceUnavailable, msgStorage)
		return
	}
	h.audit("OIDC_IDENTITY_LINKED", "user", acc.Username, "issuer", id.Issuer, "source", "self_service")
	http.Redirect(w, r, auth.PublicContinuation(h.Root, f.Continuation), http.StatusFound)
}

// completeStepUp turns a fresh provider authentication into the grant of
// the flight's intent. The answer must prove a new authentication
// (auth_time within STEP_UP_MAX_AGE_SECONDS, the asked acr); an
// administrator step-up also needs MFA assurance from the provider, as in
// the Python release.
func (h *HTTP) completeStepUp(w http.ResponseWriter, r *http.Request, p principal.Principal, f auth.Flight, acc Account, a Assessment) {
	ctx := r.Context()
	admin := f.Action != ""
	requestACR := admin
	if !admin {
		required, err := h.Proofs.ExternalIntent(ctx, p, f.Intent, methodOIDC)
		if err != nil {
			errorJSON(w, http.StatusForbidden, msgStepUpFailed)
			return
		}
		requestACR = required != auth.AssuranceBasic
	}
	if acc.ID != p.UserID || !h.Provider.fresh(a, requestACR) || (admin && a.Level == auth.AssuranceBasic) {
		h.audit("OIDC_STEP_UP_REJECTED", "user", p.Username, "reason", "insufficient_or_mismatched_assurance")
		errorJSON(w, http.StatusForbidden, msgStepUpFailed)
		return
	}
	grant, err := h.Proofs.ProveExternal(ctx, p, f.Intent, methodOIDC, a.Level)
	if err != nil {
		errorJSON(w, http.StatusForbidden, msgStepUpFailed)
		return
	}
	if admin {
		h.results.put(p.SessionID, stepUpResult{grant: grant, action: string(f.Action), expires: h.now().Add(stepUpResultTTL)})
	}
	http.Redirect(w, r, auth.PublicContinuation(h.Root, f.Continuation), http.StatusFound)
}
