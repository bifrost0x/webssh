package github

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/bifrost0x/webssh/internal/auth"
	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/store"
)

// Register adds the routes relative to APPLICATION_ROOT. The edge puts
// session, CSRF and origin checks in front of them (route catalog of
// internal/httpapi).
func (s *Service) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET "+auth.PathGitHubLogin, s.login)
	mux.HandleFunc("GET "+auth.PathGitHubCallback, s.callback)
	mux.HandleFunc("POST /api/account/github/link/start", s.linkStart)
	mux.HandleFunc("POST /api/account/step-up/github/start", s.stepUpStart)
	mux.HandleFunc("GET /api/account/github", s.status)
	mux.HandleFunc("DELETE /api/account/github", s.unlink)
	mux.HandleFunc("GET /admin/api/github-auth/config", s.adminConfig)
	mux.HandleFunc("POST /admin/api/github-auth/config", s.adminUpdate)
}

// SignIn finishes and renews browser sign-ins (*auth.Flow).
type SignIn interface {
	// SignInExternal signs in an account a redirect provider vouched for,
	// with the account's second factor when it requires one; on success it
	// has written the response.
	SignInExternal(w http.ResponseWriter, r *http.Request, in auth.ExternalSignIn) error
	// RenewAfter runs change, raises the account's generation, ends every
	// session of the account and continues this browser in a new session.
	RenewAfter(w http.ResponseWriter, r *http.Request, reason principal.Reason, change func(ctx context.Context, tx *store.Tx) error) error
}

// BindingFunc returns the browser binding of a request
// (httpapi.BrowserBinding).
type BindingFunc func(*http.Request) string

// StepUpHeader carries the step-up grant of a mutating route.
const StepUpHeader = "X-WebSSH-Step-Up"

// loginRule is the limit of the sign-in routes, "5 per minute".
var loginRule = auth.Rule{Limit: 5, Window: time.Minute}

// Texts of app/github_auth_routes.py.
const (
	msgTooMany       = "Too many GitHub login attempts"
	msgInvalidLogin  = "Invalid or expired GitHub login"
	msgUnavailable   = "GitHub authentication is temporarily unavailable"
	msgOrgRequired   = "GitHub organization membership is required"
	msgStepUpFailed  = "Step-up authentication failed"
	msgStepUpNeeded  = "Additional authentication is required"
	msgNotLinked     = "GitHub identity is not linked to a WebSSH account"
	msgInactive      = "GitHub identity is not linked to an active account"
	msgLinkFailed    = "GitHub account linking failed"
	msgAlreadyLinked = "GitHub identity is already linked"
	msgProvision     = "GitHub account could not be provisioned"
	msgNoLocalMFA    = "No active local MFA factor is available"
)

// writeError answers like jsonify({'error': msg}), status.
func writeError(w http.ResponseWriter, status int, msg string) {
	auth.WriteJSON(w, status, map[string]string{"error": msg})
}

func (s *Service) binding(r *http.Request) string {
	if s.Binding == nil {
		return ""
	}
	return s.Binding(r)
}

func (s *Service) limited(r *http.Request, endpoint string) bool {
	l := s.Limits
	l.Login = loginRule
	if !l.SourceLimited(r, endpoint) {
		return false
	}
	ip := "unknown"
	if l.ClientAddr != nil && l.ClientAddr(r) != "" {
		ip = l.ClientAddr(r)
	}
	s.audit().Security(r.Context(), slog.LevelWarn, "RATE_LIMIT_EXCEEDED", "endpoint", endpoint, "ip", ip)
	return true
}

func clientIP(s *Service, r *http.Request) string {
	if s.Limits.ClientAddr != nil {
		if a := s.Limits.ClientAddr(r); a != "" {
			return a
		}
	}
	return "unknown"
}

// begin stores a new flight for this browser and returns the authorization
// URL; it is fault.NotFound while GitHub sign-in is not active.
func (s *Service) begin(r *http.Request, f auth.Flight) (string, error) {
	ctx := r.Context()
	cfg, err := s.Configuration(ctx)
	if err != nil {
		return "", err
	}
	if !cfg.Active {
		return "", fault.New(fault.NotFound, "")
	}
	u, err := s.Begin(ctx, f)
	if err != nil {
		return "", err
	}
	if err := s.storeFlight(ctx, s.binding(r), f, cfg.Generation); err != nil {
		return "", fault.Wrap(fault.InvalidRequest, err, "")
	}
	return u, nil
}

func (s *Service) fail(w http.ResponseWriter, r *http.Request, err error) {
	if fault.Is(err, fault.NotFound) {
		http.NotFound(w, r)
		return
	}
	auth.WriteError(w, r, s.Logger, err)
}

func (s *Service) login(w http.ResponseWriter, r *http.Request) {
	if !s.Active(r.Context()) {
		http.NotFound(w, r)
		return
	}
	if s.limited(r, "github_login") {
		writeError(w, http.StatusTooManyRequests, msgTooMany)
		return
	}
	next := r.URL.Query().Get("next")
	if next == "" {
		next = "/"
	}
	f := auth.NewFlight(auth.ProviderGitHub, auth.PurposeSignIn, s.now())
	f.Nonce, f.Continuation = "", next
	u, err := s.begin(r, f)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	// #nosec G710 -- the authorization URL of the configured GitHub base; only state and challenge vary
	http.Redirect(w, r, u, http.StatusFound)
}

// stepUpStart refuses every GitHub step-up: GitHub's authorization
// response proves no fresh authentication.
func (s *Service) stepUpStart(w http.ResponseWriter, r *http.Request) {
	if !s.Active(r.Context()) {
		http.NotFound(w, r)
		return
	}
	p, err := principal.Require(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, auth.MaxBodyBytes))
	var data map[string]any
	if err != nil || decodeJSON(body, &data) != nil || data == nil {
		writeError(w, http.StatusBadRequest, "Invalid request")
		return
	}
	s.audit().Security(r.Context(), slog.LevelInfo, "ACCOUNT_STEP_UP_REJECTED", "user", p.Username, "method", "github",
		"reason", "fresh_authentication_unavailable")
	writeError(w, http.StatusForbidden, msgStepUpFailed)
}

func (s *Service) consume(w http.ResponseWriter, r *http.Request, p principal.Principal, action principal.Action, target string) bool {
	if err := s.StepUp.Consume(r.Context(), p, action, target, r.Header.Get(StepUpHeader)); err != nil {
		auth.WriteJSON(w, http.StatusForbidden, map[string]string{"error": msgStepUpNeeded, "code": string(fault.StepUpRequired)})
		return false
	}
	return true
}

func (s *Service) adminConfig(w http.ResponseWriter, r *http.Request) {
	if _, err := principal.RequireAdmin(r.Context()); err != nil {
		s.fail(w, r, err)
		return
	}
	cfg, err := s.Configuration(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	auth.WriteJSON(w, http.StatusOK, map[string]any{"configuration": cfg})
}

func (s *Service) adminUpdate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := principal.RequireAdmin(ctx)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !s.consume(w, r, p, principal.ActionGitHubConfig, "global") {
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, auth.MaxBodyBytes))
	if err != nil {
		body = nil
	}
	cfg, err := s.Update(ctx, body, p.UserID)
	switch {
	case fault.Is(err, fault.InvalidRequest):
		writeError(w, http.StatusBadRequest, "Invalid GitHub configuration")
		return
	case err != nil:
		s.audit().Security(ctx, slog.LevelError, "GITHUB_CONFIGURATION_FAILED", "admin", p.Username, "error", string(fault.CodeOf(err)))
		writeError(w, http.StatusServiceUnavailable, "GitHub configuration could not be saved")
		return
	}
	s.audit().Security(ctx, slog.LevelInfo, "GITHUB_CONFIGURATION_CHANGED", "admin", p.Username, "enabled", cfg.Enabled,
		"auto_provision", cfg.AutoProvision, "allowed_org_count", len(cfg.AllowedOrgs), "client_secret_configured", cfg.SecretConfigured)
	auth.WriteJSON(w, http.StatusOK, map[string]any{"configuration": cfg})
}
