package oidc

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/bifrost0x/webssh/internal/auth"
	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/store"
)

// SignIn finishes a provider sign-in and renews the browser session
// after an account-wide change (*auth.Flow).
type SignIn interface {
	SignInExternal(w http.ResponseWriter, r *http.Request, in auth.ExternalSignIn) error
	// RenewAfter runs change, raises the account's generation, ends every
	// session of the account and continues this browser in a new session.
	RenewAfter(w http.ResponseWriter, r *http.Request, reason principal.Reason, change func(ctx context.Context, tx *store.Tx) error) error
}

// HTTP serves the OIDC routes (oidc_routes.py and the provider parts of
// step_up_routes.py and account_step_up_routes.py). The edge mounts it
// behind its session, CSRF and origin checks; the paths of sign-in and
// callback never change (auth.PathOIDCLogin, auth.PathOIDCCallback).
type HTTP struct {
	Provider *Provider
	Links    *Links
	Flights  *auth.Flights
	SignIn   SignIn
	Accounts Accounts
	StepUp   StepUp
	Proofs   ProviderStepUp
	Sessions Sessions
	Gates    Gates
	// Binding is the browser binding of the edge (httpapi.BrowserBinding);
	// every flight is bound to it.
	Binding func(*http.Request) string
	// Limits applies OIDC_LOGIN_RATE_LIMIT (as its Login rule) per source
	// to sign-in and callback.
	Limits auth.FactorLimits
	// Root is APPLICATION_ROOT ("" at the root).
	Root   string
	Audit  Auditor
	Logger *slog.Logger
	Now    func() time.Time

	results stepUpResults
}

// Register adds the routes to mux, relative to APPLICATION_ROOT.
func (h *HTTP) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET "+auth.PathOIDCLogin, h.login)
	mux.HandleFunc("GET "+auth.PathOIDCCallback, h.callback)
	mux.HandleFunc("GET /api/account/oidc", h.accountStatus)
	mux.HandleFunc("POST /api/account/oidc/link/start", h.selfLinkStart)
	mux.HandleFunc("POST /api/account/step-up/oidc/start", h.accountStepUpStart)
	mux.HandleFunc("POST /api/step-up/oidc/start", h.adminStepUpStart)
	mux.HandleFunc("GET /api/step-up/oidc/result", h.adminStepUpResult)
	mux.HandleFunc("GET /admin/api/users/{user_id}/oidc-identities", h.adminList)
	mux.HandleFunc("POST /admin/api/users/{user_id}/oidc-link", h.adminLink)
	mux.HandleFunc("DELETE /admin/api/users/{user_id}/oidc-identities/{identity_id}", h.adminUnlink)
}

// Texts of the Python release.
const (
	msgUnavailable  = "Identity provider unavailable"
	msgInvalidLogin = "Invalid or expired OIDC login"
	msgTooMany      = "Too many OIDC login attempts"
	msgNotLinked    = "External identity is not linked to an active account"
	msgLinkFailed   = "OIDC identity linking failed"
	msgLinkRefused  = "OIDC cannot be linked to this account"
	msgLinked       = "OIDC identity is already linked"
	msgStepUpFailed = "Step-up authentication failed"
	msgStorage      = "OIDC identity storage is temporarily unavailable"
)

func (h *HTTP) now() time.Time {
	if h.Now != nil {
		return h.Now().UTC()
	}
	return time.Now().UTC()
}

func (h *HTTP) logger() *slog.Logger {
	if h.Logger != nil {
		return h.Logger
	}
	return slog.Default()
}

func (h *HTTP) audit(event string, kv ...any) {
	if h.Audit != nil {
		h.Audit.Security(event, kv...)
	}
}

// errorJSON answers {"error": msg} with status, as oidc_routes.py does.
func errorJSON(w http.ResponseWriter, status int, msg string) {
	auth.WriteJSON(w, status, map[string]any{"error": msg})
}

// active reports whether the administrator left the feature "oidc" on;
// a failure counts as off.
func (h *HTTP) active(r *http.Request) bool {
	if h.Gates == nil {
		return true
	}
	ok, err := h.Gates.Active(r.Context(), "oidc")
	return err == nil && ok
}

// start stores the flight for this browser and returns the provider's
// authorization URL; a failure drops the flight again. requestACR adds
// acr_values to a step-up.
func (h *HTTP) start(r *http.Request, f auth.Flight, requestACR bool) (string, error) {
	binding := h.Binding(r)
	if err := h.Flights.Put(binding, f); err != nil {
		return "", err
	}
	u, err := h.Provider.begin(r.Context(), f, requestACR)
	if err != nil {
		h.Flights.Drop(binding, f.State)
		h.logger().WarnContext(r.Context(), "OIDC provider unavailable", "error", err)
		return "", err
	}
	return u, nil
}

// writeStartError answers a failed start: 503 for an unreachable
// provider, 403 otherwise.
func writeStartError(w http.ResponseWriter, err error, refused string) {
	if fault.Is(err, fault.Unavailable) {
		errorJSON(w, http.StatusServiceUnavailable, msgUnavailable)
		return
	}
	errorJSON(w, http.StatusForbidden, refused)
}

func (h *HTTP) login(w http.ResponseWriter, r *http.Request) {
	if h.Limits.SourceLimited(r, "oidc_login") {
		h.audit("RATE_LIMIT_EXCEEDED", "endpoint", "oidc_login")
		errorJSON(w, http.StatusTooManyRequests, msgTooMany)
		return
	}
	if !h.active(r) {
		http.NotFound(w, r)
		return
	}
	f := auth.NewFlight(auth.ProviderOIDC, auth.PurposeSignIn, h.now())
	next := r.URL.Query().Get("next")
	if next == "" {
		next = "/"
	}
	f.Continuation = auth.SafeContinuation(next)
	u, err := h.start(r, f, false)
	if err != nil {
		writeStartError(w, err, msgUnavailable)
		return
	}
	// u is the authorization endpoint of the configured issuer's discovery
	// document (https, checked in discover); "next" only reaches the flight.
	http.Redirect(w, r, u, http.StatusFound) // #nosec G710 -- the target is the provider's checked endpoint, not request input
}

// principalOf returns the signed-in principal of the request, if any.
func principalOf(r *http.Request) (principal.Principal, bool) {
	p, ok := principal.From(r.Context())
	return p, ok && p.Valid()
}
