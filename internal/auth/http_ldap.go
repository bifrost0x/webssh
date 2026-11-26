package auth

import (
	"net/http"
	"strconv"
	"strings"
	"unicode"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/session"
)

// maxLDAPFormBytes bounds the directory sign-in form (_MAX_LDAP_FORM_BYTES).
const maxLDAPFormBytes = 4096

// Texts of ldap_routes.py.
const (
	msgLDAPInvalid     = "Invalid username or password"
	msgLDAPUnavailable = "Directory sign-in is temporarily unavailable"
)

// DirectorySignIn is the directory form of the sign-in page,
// POST /login/ldap (PathLDAPLogin). Provider checks name and password
// against the directory (internal/auth/ldap): fault.AuthFailed for every
// refusal, fault.Unavailable when the directory gives no verdict, which
// does not count as a failed attempt.
type DirectorySignIn struct {
	Flow     *Flow
	Provider Provider
	// Active reports whether the security feature "ldap" is on; off
	// answers 404 like the Python feature gate.
	Active func(r *http.Request) bool
	// Rule is LDAP_LOGIN_RATE_LIMIT per source address.
	Rule Rule
}

// Register adds the route relative to APPLICATION_ROOT.
func (d *DirectorySignIn) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST "+PathLDAPLogin, d.login)
}

func (d *DirectorySignIn) page(w http.ResponseWriter, r *http.Request, status int, msg string) {
	d.Flow.Pages.Login(w, r, status, LoginView{AuthSource: "ldap", LDAPError: msg})
}

func (d *DirectorySignIn) login(w http.ResponseWriter, r *http.Request) {
	f := d.Flow
	if d.Active != nil && !d.Active(r) {
		http.NotFound(w, r)
		return
	}
	if f.signedIn(r) {
		f.redirect(w, r, f.url("/"))
		return
	}
	if r.ContentLength > maxLDAPFormBytes {
		d.page(w, r, http.StatusRequestEntityTooLarge, "")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxLDAPFormBytes)
	if err := r.ParseForm(); err != nil {
		d.page(w, r, http.StatusRequestEntityTooLarge, "")
		return
	}
	ctx := r.Context()
	ip := f.clientIP(r)
	presented, password := r.PostFormValue("username"), r.PostFormValue("password")
	username := strings.TrimFunc(presented, isPythonSpace)
	limited := func(endpoint, user string) {
		if f.Audit != nil {
			f.Audit.RateLimitExceeded(endpoint, ip, user)
		}
		d.page(w, r, http.StatusTooManyRequests, msgTooManyLogins)
	}
	if f.Limits.Enabled {
		if ok, _ := f.Limiter.Allow("ldap_login:"+SourceBucket(ip, f.ipPrefix(ctx)), d.Rule); !ok {
			limited("ldap_login", "")
			return
		}
	}
	var reservation []Reservation
	if f.Limits.Enabled {
		var ok bool
		if reservation, ok = f.reserveUsername(ctx, "ldap_login", username, ip, f.Devices.Trusted(r, username)); !ok {
			limited("ldap_login_username", username)
			return
		}
	}
	userID, err := d.Provider.Authenticate(ctx, presented, password)
	switch {
	case fault.Is(err, fault.AuthFailed):
		if f.Audit != nil {
			f.Audit.Security("LDAP_LOGIN_REJECTED", "user", username, "ip", ip, "reason", "invalid_credentials_or_mapping")
		}
		d.page(w, r, http.StatusUnauthorized, msgLDAPInvalid)
		return
	case err != nil:
		f.Limiter.Release(reservation...)
		f.logger().ErrorContext(ctx, "directory sign-in unavailable", "error", err)
		if f.Audit != nil {
			f.Audit.Security("LDAP_LOGIN_UNAVAILABLE", "user", username, "ip", ip)
		}
		d.page(w, r, http.StatusServiceUnavailable, msgLDAPUnavailable)
		return
	}
	f.Limiter.Release(reservation...)
	if err := d.finish(w, r, userID, username); err != nil {
		f.fail(w, r, err)
	}
}

// finish starts the pending sign-in of the verified directory account:
// the second factor when the account requires one, otherwise the session
// at once. The continuation is the root, as in the Python release. The
// browser becomes a known device for the submitted name, as after a local
// password.
func (d *DirectorySignIn) finish(w http.ResponseWriter, r *http.Request, userID int64, username string) error {
	f, ctx := d.Flow, r.Context()
	acc, err := f.Accounts.Get(ctx, userID)
	if err != nil {
		return err
	}
	f.Devices.Remember(w, acc, username)
	p := Pending{UserID: userID, Generation: acc.AuthGeneration, PrimaryMethod: d.Provider.Name(), Assurance: session.Basic,
		Remember: r.PostFormValue("remember") == "on", Continuation: "/"}
	if acc.MFARequired {
		if err := f.pending().begin(ctx, f.binding(r), p); err != nil {
			return err
		}
		methods := f.methods(ctx, userID)
		if wantsJSON(r) {
			WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "mfa_required": true, "methods": methods})
			return nil
		}
		f.Pages.Login(w, r, http.StatusOK, LoginView{AuthSource: "ldap", MFARequired: true, MFAMethods: methods})
		return nil
	}
	if err := f.finalize(ctx, w, p, []string{p.PrimaryMethod}); err != nil {
		return err
	}
	f.redirect(w, r, PublicContinuation(f.Root, p.Continuation))
	return nil
}

// wantsJSON is request.accept_mimetypes.best == "application/json": the
// first media type of the Accept header with the highest quality.
func wantsJSON(r *http.Request) bool {
	best, bestQ := "", -1.0
	for part := range strings.SplitSeq(r.Header.Get("Accept"), ",") {
		media, params, _ := strings.Cut(strings.TrimSpace(part), ";")
		q := 1.0
		for p := range strings.SplitSeq(params, ";") {
			if k, v, ok := strings.Cut(strings.TrimSpace(p), "="); ok && strings.TrimSpace(k) == "q" {
				if parsed, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil {
					q = parsed
				}
			}
		}
		if media = strings.ToLower(strings.TrimSpace(media)); media != "" && q > bestQ {
			best, bestQ = media, q
		}
	}
	return best == "application/json"
}

// isPythonSpace is Python's str.isspace for strip(): Unicode White_Space
// plus the separators U+001C to U+001F.
func isPythonSpace(r rune) bool { return unicode.IsSpace(r) || (r >= 0x1c && r <= 0x1f) }
