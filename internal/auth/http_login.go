package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"github.com/bifrost0x/webssh/internal/accounts"
	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/session"
)

// maxFormBytes bounds the sign-in forms.
const maxFormBytes = 64 << 10

// Texts of the Python release.
const (
	msgTooManyLogins   = "Too many login attempts. Please try again later."
	msgPartialLogout   = "You were signed out in this browser, but the server could not end your session. Change your password or ask an administrator to end your sessions."
	msgRegistrationOff = "Registration is currently disabled."
)

// Register adds the sign-in routes relative to APPLICATION_ROOT. The edge
// puts CSRF and origin checks in front of the POST routes.
func (f *Flow) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /login", f.loginPage)
	mux.HandleFunc("POST /login", f.login)
	mux.HandleFunc("POST /login/cancel", f.cancel)
	mux.HandleFunc("GET /register", f.registerPage)
	mux.HandleFunc("POST /register", f.register)
	mux.HandleFunc("POST /logout", f.logout)
	mux.HandleFunc("GET /change-password", f.passwordPage)
	mux.HandleFunc("POST /change-password", f.changePassword)
}

func (f *Flow) bootstrapOpen(ctx context.Context) (bool, error) {
	if !f.Bootstrap {
		return false, nil
	}
	has, err := f.Accounts.HasAccounts(ctx)
	return !has, err
}

func (f *Flow) fail(w http.ResponseWriter, r *http.Request, err error) {
	status, code, _ := fault.Status(err)
	if status >= 500 {
		f.logger().ErrorContext(r.Context(), "sign-in request failed", "path", r.URL.Path, "code", code, "error", err)
	}
	f.Pages.Error(w, r, status)
}

func (f *Flow) loginPage(w http.ResponseWriter, r *http.Request) {
	if f.signedIn(r) {
		f.redirect(w, r, f.url("/"))
		return
	}
	open, err := f.bootstrapOpen(r.Context())
	if err != nil {
		f.fail(w, r, err)
		return
	}
	if open {
		f.redirect(w, r, f.url("/register"))
		return
	}
	f.Pages.Login(w, r, http.StatusOK, LoginView{Flashes: f.TakeFlashes(r)})
}

// usernameKey is the limiter key part for a submitted name: a digest of
// the trimmed, case-folded name, kept whether or not an account exists.
func usernameKey(name string) string {
	sum := sha256.Sum256([]byte(accounts.FoldName(strings.TrimSpace(name))))
	return hex.EncodeToString(sum[:16])
}

// reserveUsername is reserve_login_username_attempt: one attempt per
// name and source bucket, then either the failure budget of a valid
// known-device cookie (device is its nonce) or the per-name ceiling across
// all sources. Only failed attempts keep their reservations. The buckets
// belong to one endpoint ("login", "ldap_login"), as in Python.
func (f *Flow) reserveUsername(ctx context.Context, endpoint, name, source, device string) ([]Reservation, bool) {
	if strings.TrimSpace(name) == "" {
		return nil, true
	}
	perSource, global, prefix := DefaultUsernameRule.Limit, DefaultGlobalRule.Limit, 128
	if f.Settings != nil {
		if a, b, c, err := f.Settings.LoginLimits(ctx); err == nil {
			perSource, global, prefix = a, b, c
		}
	}
	key := endpoint + ":username:" + usernameKey(name)
	src, ok, _ := f.Limiter.Reserve(key+":"+SourceBucket(source, prefix), Rule{Limit: perSource, Window: time.Minute})
	if !ok {
		return nil, false
	}
	if device != "" {
		if dev, ok, _ := f.Limiter.ReserveAccount(DeviceBudgetKey(endpoint, device), Rule{Limit: DeviceFailureBudget, Window: DeviceFailureWindow}); ok {
			return []Reservation{src, dev}, true
		}
	}
	all, ok, _ := f.Limiter.ReserveAccount(key, Rule{Limit: global, Window: time.Minute})
	if !ok {
		f.Limiter.Release(src)
		return nil, false
	}
	return []Reservation{src, all}, true
}

func (f *Flow) ipPrefix(ctx context.Context) int {
	return sourcePrefix(ctx, f.Settings)
}

// sourcePrefix is ratelimit_ipv6_prefix, or 128 when it cannot be read.
func sourcePrefix(ctx context.Context, s SignInSettings) int {
	if s != nil {
		if _, _, p, err := s.LoginLimits(ctx); err == nil {
			return p
		}
	}
	return 128
}

func (f *Flow) login(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if f.signedIn(r) {
		f.redirect(w, r, f.url("/"))
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	ip := f.clientIP(r)
	limited := func(endpoint, user string) {
		if f.Audit != nil {
			f.Audit.RateLimitExceeded(endpoint, ip, user)
		}
		f.Pages.Login(w, r, http.StatusOK, LoginView{AuthSource: "local", Flashes: []Flash{{"error", msgTooManyLogins}}})
	}
	if f.Limits.Enabled {
		if ok, _ := f.Limiter.Allow("login:"+SourceBucket(ip, f.ipPrefix(ctx)), f.Limits.Login); !ok {
			limited("login", "")
			return
		}
	}
	username, password := r.PostFormValue("username"), r.PostFormValue("password")
	var reservation []Reservation
	if f.Limits.Enabled {
		var ok bool
		if reservation, ok = f.reserveUsername(ctx, "login", username, ip, f.Devices.Trusted(r, username)); !ok {
			limited("login_username", username)
			return
		}
	}
	// The session is bound to the auth_generation in effect before the
	// password was checked: a password change, reset or MFA reset that
	// commits while the hash is verified raises it, and the sign-in is
	// refused instead of outliving the change.
	before, err := f.Accounts.ByUsername(ctx, username)
	if err != nil && !fault.Is(err, fault.NotFound) {
		f.fail(w, r, err)
		return
	}
	userID, err := f.Password.Authenticate(ctx, username, password)
	if err != nil {
		if !fault.Is(err, fault.AuthFailed) {
			f.fail(w, r, err)
			return
		}
		if f.Audit != nil {
			f.Audit.LoginAttempt(username, false, ip, r.UserAgent())
		}
		f.Pages.Login(w, r, http.StatusOK, LoginView{AuthSource: "local", Flashes: []Flash{{"error", "Invalid username or password"}}})
		return
	}
	f.Limiter.Release(reservation...)
	acc, err := f.Accounts.Get(ctx, userID)
	if err != nil {
		f.fail(w, r, err)
		return
	}
	if before.ID != userID || before.AuthGeneration != acc.AuthGeneration {
		f.logger().WarnContext(ctx, "sign-in refused: credentials changed during the check", "user_id", userID)
		f.Pages.Login(w, r, http.StatusOK, LoginView{AuthSource: "local", Flashes: []Flash{{"error", "Invalid username or password"}}})
		return
	}
	f.Devices.Remember(w, acc, username)
	next := r.URL.Query().Get("next")
	if next == "" {
		next = "/"
	}
	p := Pending{UserID: userID, Generation: acc.AuthGeneration, PrimaryMethod: f.Password.Name(), Assurance: session.Basic,
		Remember: r.PostFormValue("remember") == "on", Continuation: SafeContinuation(next)}
	if acc.MFARequired {
		// The pending sign-in is no principal, so the CSRF token of the
		// page rendered here stays valid for the factor step.
		if err := f.pending().begin(ctx, f.binding(r), p); err != nil {
			f.fail(w, r, err)
			return
		}
		f.Pages.Login(w, r, http.StatusOK, LoginView{AuthSource: "local", MFARequired: true, MFAMethods: f.methods(ctx, userID)})
		return
	}
	if err := f.finalize(ctx, w, p, []string{p.PrimaryMethod}); err != nil {
		f.fail(w, r, err)
		return
	}
	f.redirect(w, r, PublicContinuation(f.Root, p.Continuation))
}

func (f *Flow) cancel(w http.ResponseWriter, r *http.Request) {
	if f.signedIn(r) {
		f.redirect(w, r, f.url("/"))
		return
	}
	if err := f.pending().cancel(r.Context(), f.binding(r)); err != nil {
		f.logger().WarnContext(r.Context(), "Pending authentication cancellation failed", "error", err)
	}
	f.redirect(w, r, f.url("/login"))
}

// logout ends the current session only. Its realtime connections close
// at once through the revocation event; other browsers of the account stay
// signed in.
func (f *Flow) logout(w http.ResponseWriter, r *http.Request) {
	p, err := principal.RequireAllowingRecovery(r.Context())
	if err != nil {
		f.redirect(w, r, f.url("/login"))
		return
	}
	ctx := r.Context()
	if f.Audit != nil {
		f.Audit.Logout(p.Username, f.clientIP(r))
	}
	ended := true
	if err := f.Sessions.Revoke(ctx, p.SessionID, principal.ReasonLogout); err != nil {
		f.logger().WarnContext(ctx, "Authentication session deletion failed during logout", "user_id", p.UserID, "error", err)
		// A copied cookie must not outlive the sign-out: end every
		// session of the account instead.
		if _, err := f.Sessions.RevokeUser(ctx, p.UserID, principal.ReasonLogout, ""); err != nil {
			ended = false
			f.logger().WarnContext(ctx, "Authentication invalidation failed during logout", "user_id", p.UserID, "error", err)
		}
	}
	f.Cookie.Clear(w)
	if !ended {
		f.AddFlash(r, Flash{"error", msgPartialLogout})
	}
	f.redirect(w, r, f.url("/login"))
}
