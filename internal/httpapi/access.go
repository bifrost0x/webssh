package httpapi

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
)

var (
	errNotFound     = fault.New(fault.NotFound, "")
	errSignIn       = fault.New(fault.AuthenticationNeeded, "")
	errForbidden    = fault.New(fault.Forbidden, "")
	errRecoveryOnly = fault.New(fault.RecoveryRequired, "A replacement factor or explicit MFA disable is required") // Python text
)

// lookupSession resolves the session cookie. ok is false when the request was
// answered (a lookup failure). A cookie that names no valid session is
// removed from the browser, as clear_browser_authentication does.
func (h *Handler) lookupSession(w http.ResponseWriter, r *http.Request) (principal.Principal, bool) {
	c, err := r.Cookie(h.session.name)
	if err != nil || c.Value == "" {
		return principal.Principal{}, true
	}
	p, err := h.sessions.Authenticate(r.Context(), c.Value)
	if err == nil && p.Valid() {
		return p, true
	}
	if err != nil && fault.CodeOf(err) != fault.AuthenticationNeeded {
		h.log.ErrorContext(r.Context(), "session lookup failed", "err", err)
		writeFault(w, r, h.log, fault.Wrap(fault.Unavailable, err, ""))
		return principal.Principal{}, false
	}
	h.session.clear(w)
	return principal.Principal{}, true
}

// authenticate puts the principal and the CSRF state into the request and
// enforces the route's access level. It returns false when it answered
// the request.
func (h *Handler) authenticate(w http.ResponseWriter, r *http.Request, access Access) (*http.Request, bool) {
	p, ok := h.lookupSession(w, r)
	if !ok {
		return r, false
	}
	signedIn := p.Valid()
	ctx := h.csrfBegin(w, r, p.SessionID)
	if signedIn {
		ctx = principal.With(ctx, p)
	}
	r = r.WithContext(ctx)
	switch access {
	case AccessPublic:
		return r, true
	case AccessUser, AccessRepair, AccessAdmin:
	default:
		h.fail(w, r, errNotFound, "", "")
		return r, false
	}
	if !signedIn {
		h.unauthorized(w, r)
		return r, false
	}
	if p.Recovery && access != AccessRepair {
		h.fail(w, r, errRecoveryOnly, kindForbidden, "")
		return r, false
	}
	if access == AccessAdmin && !p.IsAdmin {
		h.log.WarnContext(r.Context(), "unauthorized admin access attempt", "user_id", p.UserID, "path", r.URL.Path)
		h.fail(w, r, errForbidden, kindForbidden, "")
		return r, false
	}
	return r, true
}

// unauthorized answers a request without a valid session: 401 JSON for
// API clients (fix: the Python release redirected them to the sign-in
// page with 302), otherwise a redirect to the sign-in page that returns
// to this page.
func (h *Handler) unauthorized(w http.ResponseWriter, r *http.Request) {
	if wantsJSON(r) {
		writeFault(w, r, h.log, errSignIn)
		return
	}
	base := BasePath(r)
	next := base + r.URL.EscapedPath()
	if r.URL.RawQuery != "" {
		next += "?" + r.URL.RawQuery
	}
	target := base + pathLogin + "?next=" + url.QueryEscape(next)
	http.Redirect(w, r, target, http.StatusFound)
}

// csrfFailed answers a missing or wrong token. Pages get the "form
// expired" page with a link back to the form; when the browser dropped the
// Secure session cookie on a plain HTTP address the page says so instead.
func (h *Handler) csrfFailed(w http.ResponseWriter, r *http.Request, pattern string) {
	if wantsJSON(r) {
		writeFault(w, r, h.log, errCSRF)
		return
	}
	// The link is built from the matched route, never from the raw path,
	// so a crafted path cannot point outside WebSSH.
	action := pathLogin
	if _, path, _ := strings.Cut(pattern, " "); path != "" && !strings.Contains(path, "{") && path != "/logout" {
		action = path
	}
	if h.cfg.Cookies.Secure && infoFrom(r).Scheme != "https" && !reachedOverHTTPS(r) && !hasCookie(r, h.binding.name) {
		h.fail(w, r, errCSRF, kindCookieRejected, pathLogin)
		return
	}
	h.fail(w, r, errCSRF, kindFormExpired, action)
}

func hasCookie(r *http.Request, name string) bool {
	_, err := r.Cookie(name)
	return err == nil
}

// reachedOverHTTPS reports whether the browser's page was served over
// HTTPS from the host the request names, as transport_security.py
// decides behind a proxy that is not trusted: Origin, or the Referer the
// referrer policy keeps for same-origin requests.
func reachedOverHTTPS(r *http.Request) bool {
	source := r.Header.Get("Origin")
	if source == "" || source == "null" {
		source = r.Header.Get("Referer")
	}
	u, err := url.Parse(source)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return false
	}
	host := infoFrom(r).Host
	return host != "" && httpsAuthority(u.Host) == httpsAuthority(host)
}

func httpsAuthority(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if strings.HasSuffix(v, ":443") && !strings.HasSuffix(v, "]") {
		v = strings.TrimSuffix(v, ":443")
	}
	return v
}
