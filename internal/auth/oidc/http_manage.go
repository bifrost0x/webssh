package oidc

import (
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bifrost0x/webssh/internal/auth"
	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
)

// identityJSON is one identity as the account page and the
// administration list it (oidc_routes.py); the subject only for
// administrators.
type identityJSON struct {
	ID        int64  `json:"id"`
	Issuer    string `json:"issuer"`
	Subject   string `json:"subject,omitzero"`
	CreatedAt string `json:"created_at"`
}

// isoformat is Python's datetime.isoformat() of the naive UTC value.
func isoformat(t time.Time) string {
	t = t.UTC()
	if t.Nanosecond()/1000 == 0 {
		return t.Format("2006-01-02T15:04:05")
	}
	return t.Format("2006-01-02T15:04:05.000000")
}

func (h *HTTP) identities(w http.ResponseWriter, r *http.Request, userID int64, withSubject bool) {
	list, err := h.Links.List(r.Context(), userID)
	if err != nil {
		auth.WriteError(w, r, h.Logger, err)
		return
	}
	out := make([]identityJSON, 0, len(list))
	for _, li := range list {
		j := identityJSON{ID: li.ID, Issuer: li.Issuer, CreatedAt: isoformat(li.CreatedAt)}
		if withSubject {
			j.Subject = li.Subject
		}
		out = append(out, j)
	}
	auth.WriteJSON(w, http.StatusOK, map[string]any{"identities": out})
}

func (h *HTTP) accountStatus(w http.ResponseWriter, r *http.Request) {
	p, err := principal.Require(r.Context())
	if err != nil {
		auth.WriteError(w, r, h.Logger, err)
		return
	}
	h.identities(w, r, p.UserID, false)
}

// selfLinkStart starts linking an identity to the own account after the
// oidc.self_link step-up; the provider is asked to authenticate again.
func (h *HTTP) selfLinkStart(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := principal.Require(ctx)
	if err != nil {
		auth.WriteError(w, r, h.Logger, err)
		return
	}
	if err := h.StepUp.Consume(ctx, p, principal.ActionOIDCSelfLink, strconv.FormatInt(p.UserID, 10), r.Header.Get(auth.StepUpHeader)); err != nil {
		auth.WriteError(w, r, h.Logger, err)
		return
	}
	if !h.active(r) {
		http.NotFound(w, r)
		return
	}
	acc, err := h.Accounts.OIDCAccount(ctx, p.UserID)
	if err != nil || acc.Locked {
		errorJSON(w, http.StatusForbidden, msgLinkFailed)
		return
	}
	if acc.Managed != "" {
		errorJSON(w, http.StatusConflict, msgLinkRefused)
		return
	}
	f := auth.NewFlight(auth.ProviderOIDC, auth.PurposeLink, h.now())
	f.UserID, f.Generation, f.SessionID, f.Continuation = p.UserID, acc.Generation, p.SessionID, "/settings"
	u, err := h.start(r, f, false)
	if err != nil {
		writeStartError(w, err, msgLinkFailed)
		return
	}
	auth.WriteJSON(w, http.StatusOK, map[string]any{"authorization_url": u})
}

// stepUpFlight is a step-up flight of p for intent; action and target are
// those of an administrator step-up, empty for an account step-up.
func (h *HTTP) stepUpFlight(r *http.Request, p principal.Principal, action principal.Action, target, intent, continuation string) (auth.Flight, bool) {
	acc, err := h.Accounts.OIDCAccount(r.Context(), p.UserID)
	if err != nil || acc.Locked {
		return auth.Flight{}, false
	}
	f := auth.NewFlight(auth.ProviderOIDC, auth.PurposeStepUp, h.now())
	f.UserID, f.Generation, f.SessionID = p.UserID, acc.Generation, p.SessionID
	f.Action, f.Target, f.Intent, f.Continuation = action, target, intent, continuation
	return f, true
}

func stepUpRefused(w http.ResponseWriter, status int) {
	auth.WriteJSON(w, status, map[string]any{"code": string(fault.StepUpFailed), "error": msgStepUpFailed})
}

// accountStepUpStart proves an account intent at the provider
// (/api/account/step-up/oidc/start); the page then polls the step-up
// status for the grant.
func (h *HTTP) accountStepUpStart(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := principal.Require(ctx)
	if err != nil {
		auth.WriteError(w, r, h.Logger, err)
		return
	}
	token, _ := auth.ReadObject(w, r).String("intent")
	required, err := h.Proofs.ExternalIntent(ctx, p, token, methodOIDC)
	if err != nil || !h.active(r) {
		stepUpRefused(w, http.StatusForbidden)
		return
	}
	if h.Limits.ReauthLimited(r, p.UserID, "oidc_start") {
		auth.WriteError(w, r, h.Logger, fault.New(fault.RateLimited, msgStepUpFailed))
		return
	}
	f, ok := h.stepUpFlight(r, p, "", "", token, "/settings")
	if !ok {
		stepUpRefused(w, http.StatusForbidden)
		return
	}
	u, err := h.start(r, f, required != auth.AssuranceBasic)
	if err != nil {
		writeStartError(w, err, msgStepUpFailed)
		return
	}
	auth.WriteJSON(w, http.StatusOK, map[string]any{"authorization_url": u})
}

var integerTarget = regexp.MustCompile(`^-?(0|[1-9][0-9]*)$`)

// readIntent reads action and target of the administrator family: the
// target is a string or an integer, as step_up_routes._intent accepts.
func readIntent(body auth.Object) (principal.Action, string, bool) {
	name, _ := body.String("action")
	action := principal.Action(strings.TrimSpace(name))
	target := ""
	if raw, ok := body["target"]; ok {
		switch raw.Kind() {
		case '"':
			target, _ = body.String("target")
		case '0':
			if !integerTarget.MatchString(string(raw)) {
				return "", "", false
			}
			if target = string(raw); target == "-0" {
				target = "0"
			}
		default:
			return "", "", false
		}
	}
	return action, target, action.Known() && target != ""
}

// adminStepUpStart proves an administrator action at the provider
// (/api/step-up/oidc/start); the page then fetches the grant from
// /api/step-up/oidc/result.
func (h *HTTP) adminStepUpStart(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := principal.RequireAdmin(ctx)
	if err != nil {
		auth.WriteError(w, r, h.Logger, err)
		return
	}
	action, target, ok := readIntent(auth.ReadObject(w, r))
	if !ok {
		stepUpRefused(w, http.StatusBadRequest)
		return
	}
	if !h.active(r) {
		stepUpRefused(w, http.StatusForbidden)
		return
	}
	intent, err := h.Proofs.BeginExternal(ctx, p, action, target, methodOIDC)
	if err != nil {
		stepUpRefused(w, http.StatusForbidden)
		return
	}
	f, ok := h.stepUpFlight(r, p, action, target, intent, "/admin")
	if !ok {
		stepUpRefused(w, http.StatusForbidden)
		return
	}
	u, err := h.start(r, f, true)
	if err != nil {
		writeStartError(w, err, msgStepUpFailed)
		return
	}
	auth.WriteJSON(w, http.StatusOK, map[string]any{"authorization_url": u})
}

func (h *HTTP) adminStepUpResult(w http.ResponseWriter, r *http.Request) {
	p, err := principal.RequireAdmin(r.Context())
	if err != nil {
		auth.WriteError(w, r, h.Logger, err)
		return
	}
	res, ok := h.results.take(p.SessionID, h.now())
	if !ok {
		stepUpRefused(w, http.StatusNotFound)
		return
	}
	auth.WriteJSON(w, http.StatusOK, map[string]any{"grant": res.grant, "action": res.action,
		"expires_in": max(0, int(res.expires.Sub(h.now())/time.Second))})
}

// stepUpResultTTL is how long the grant of an administrator step-up waits
// for the page (the five minutes of _oidc_step_up_result).
const stepUpResultTTL = 5 * time.Minute

const maxStepUpResults = 1024

type stepUpResult struct {
	grant, action string
	expires       time.Time
}

// stepUpResults keeps one result per browser session until the page
// fetches it.
type stepUpResults struct {
	mu sync.Mutex
	m  map[string]stepUpResult
}

func (s *stepUpResults) put(sessionID string, res stepUpResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil {
		s.m = map[string]stepUpResult{}
	}
	now := res.expires.Add(-stepUpResultTTL)
	for k, v := range s.m {
		if !now.Before(v.expires) {
			delete(s.m, k)
		}
	}
	if _, replace := s.m[sessionID]; !replace && len(s.m) >= maxStepUpResults {
		return
	}
	s.m[sessionID] = res
}

func (s *stepUpResults) take(sessionID string, now time.Time) (stepUpResult, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	res, ok := s.m[sessionID]
	if ok {
		delete(s.m, sessionID)
	}
	return res, ok && now.Before(res.expires)
}
