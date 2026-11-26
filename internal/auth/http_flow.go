package auth

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/bifrost0x/webssh/internal/accounts"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/session"
	"github.com/bifrost0x/webssh/internal/store"
)

// Passwords is the local password store for the change-password form
// (provided by internal/auth/local).
type Passwords interface {
	Matches(ctx context.Context, userID int64, password string) (bool, error)
	ValidateNew(password string) string
	Hash(ctx context.Context, password string) (string, error)
	StoreTx(ctx context.Context, tx *store.Tx, userID int64, hash string) error
}

// SignInSettings are the administrator settings the sign-in reads
// (provided by internal/settings): whether ongoing registration is open,
// and the sign-in protection values login_username_limit,
// login_username_global_limit (per minute) and ratelimit_ipv6_prefix.
type SignInSettings interface {
	RegistrationEnabled(ctx context.Context) (bool, error)
	LoginLimits(ctx context.Context) (perSource, global, ipv6Prefix int, err error)
}

// Auditor writes the security audit log (provided by internal/audit).
type Auditor interface {
	Security(event string, kv ...any)
	LoginAttempt(username string, ok bool, ip, userAgent string)
	Logout(username, ip string)
	Registration(username string, ok bool, ip string)
	PasswordChange(username string, ok bool, ip string)
	RateLimitExceeded(endpoint, ip, user string)
}

// LoginView is what the sign-in page shows.
type LoginView struct {
	Flashes     []Flash
	AuthSource  string // "local" after a submitted form, else ""
	MFARequired bool
	MFAMethods  []string
}

// FormView is what the registration and change-password pages show.
type FormView struct {
	Flashes []Flash
}

// Pages renders the server-side pages (internal/httpapi through
// cmd/webssh). Each call writes the whole response.
type Pages interface {
	Login(w http.ResponseWriter, r *http.Request, status int, v LoginView)
	Register(w http.ResponseWriter, r *http.Request, status int, v FormView)
	ChangePassword(w http.ResponseWriter, r *http.Request, status int, v FormView)
	Error(w http.ResponseWriter, r *http.Request, status int)
}

// SessionCookie writes the session cookie (httpapi.SessionCookie). A
// zero expiry makes a browser-session cookie.
type SessionCookie interface {
	Set(w http.ResponseWriter, token string, expires time.Time)
	Clear(w http.ResponseWriter)
}

// Limits are the rate limits of the sign-in forms (RATELIMIT_*).
type Limits struct {
	Enabled bool
	Login   Rule // RATELIMIT_LOGIN_LIMIT
	Default Rule // RATELIMIT_DEFAULT (registration)
}

// Flow runs the browser sign-in: password form, pending second factor,
// cancel, registration, sign-out and password change. Second factors
// finish a pending sign-in through PendingUser and CompletePending.
type Flow struct {
	DB       *store.DB
	MAC      MAC
	Accounts *accounts.Service
	Sessions *session.Service
	Cookie   SessionCookie
	// Binding returns the browser binding the HTTP edge keeps in its
	// binding cookie (httpapi.BrowserBinding); pending sign-ins and
	// flash messages are tied to it.
	Binding   func(*http.Request) string
	Password  Provider // the local provider
	Passwords Passwords
	Factors   []Factor
	Gates     Gates
	Settings  SignInSettings
	Limiter   *Limiter
	Limits    Limits
	// Devices issues and checks known-device cookies; nil applies the
	// per-name ceiling to every browser.
	Devices *Devices
	Audit   Auditor
	Pages   Pages
	// Root is APPLICATION_ROOT ("" at the root).
	Root string
	// Bootstrap is BOOTSTRAP_REGISTRATION_ENABLED.
	Bootstrap bool
	// ClientAddr returns the client address after the proxy rules of the
	// HTTP edge (httpapi.ClientAddr); nil uses the connection's address.
	ClientAddr func(*http.Request) netip.Addr
	Logger     *slog.Logger
	Now        func() time.Time

	flash flashes
}

func (f *Flow) now() time.Time {
	if f.Now != nil {
		return f.Now().UTC()
	}
	return time.Now().UTC()
}

func (f *Flow) logger() *slog.Logger {
	if f.Logger != nil {
		return f.Logger
	}
	return slog.Default()
}

func (f *Flow) pending() pendingStore { return pendingStore{db: f.DB, mac: f.MAC, now: f.now} }

func (f *Flow) clientIP(r *http.Request) string {
	if f.ClientAddr != nil {
		if a := f.ClientAddr(r); a.IsValid() {
			return a.String()
		}
		return "unknown"
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

func (f *Flow) url(path string) string { return strings.TrimRight(f.Root, "/") + path }

func (f *Flow) redirect(w http.ResponseWriter, r *http.Request, path string) {
	http.Redirect(w, r, path, http.StatusFound)
}

// signedIn reports whether the request carries a valid session; the
// edge puts its principal into the context also on public routes.
func (f *Flow) signedIn(r *http.Request) bool {
	_, ok := principal.From(r.Context())
	return ok
}

func (f *Flow) binding(r *http.Request) string {
	if f.Binding == nil {
		return ""
	}
	return f.Binding(r)
}

// AddFlash queues messages for the next page of this browser.
func (f *Flow) AddFlash(r *http.Request, msgs ...Flash) {
	f.flash.add(f.now(), f.binding(r), msgs...)
}

// TakeFlashes returns and removes the queued messages of this browser;
// the workspace page calls it too.
func (f *Flow) TakeFlashes(r *http.Request) []Flash {
	return f.flash.take(f.now(), f.binding(r))
}

// methods returns the enrolled factors whose feature is active, in the
// order passkey, totp, recovery (available_mfa_methods).
func (f *Flow) methods(ctx context.Context, userID int64) []string {
	var out []string
	for _, kind := range []string{"passkey", "totp", "recovery"} {
		fac := f.factor(kind)
		if fac == nil {
			continue
		}
		if active, err := f.Gates.Active(ctx, kind); err != nil || !active {
			continue
		}
		if ok, err := fac.Enrolled(ctx, userID); err == nil && ok {
			out = append(out, kind)
		}
	}
	return out
}

func (f *Flow) factor(kind string) Factor {
	for _, fac := range f.Factors {
		if fac.Kind() == kind {
			return fac
		}
	}
	return nil
}

// finalize issues the session of a completed sign-in, sets its cookie and
// records it (finalize_login). The account must still be eligible under
// the generation the primary credential was checked against.
// The caller answers with a redirect or JSON: the CSRF token of the page
// changes with the new session.
func (f *Flow) finalize(ctx context.Context, w http.ResponseWriter, p Pending, methods []string) error {
	sess, token, err := f.Sessions.Issue(ctx, session.IssueRequest{
		UserID: p.UserID, Generation: p.Generation, PrimaryMethod: p.PrimaryMethod, Methods: methods,
		Assurance: p.Assurance, Remember: p.Remember,
	})
	if err != nil {
		return err
	}
	var expires time.Time
	if sess.Remember {
		expires = sess.ExpiresAt
	}
	f.Cookie.Set(w, token, expires)
	if err := f.Accounts.RecordSignIn(ctx, p.UserID); err != nil {
		f.logger().WarnContext(ctx, "last sign-in time not stored", "user_id", p.UserID, "error", err)
	}
	if f.Audit != nil {
		name := ""
		if a, err := f.Accounts.Get(ctx, p.UserID); err == nil {
			name = a.Username
		}
		f.Audit.Security("AUTHENTICATION_SUCCESS", "user", name, "primary_method", p.PrimaryMethod,
			"assurance", string(p.Assurance), "methods", strings.Join(methods, ","))
	}
	return nil
}

// PendingUser returns the account of this browser's pending sign-in; a
// missing or expired one is fault.MFARestart.
func (f *Flow) PendingUser(r *http.Request) (int64, error) {
	p, err := f.pending().peek(r.Context(), f.binding(r))
	if err != nil {
		return 0, err
	}
	return p.UserID, nil
}

// CompletePending finishes this browser's pending sign-in after the
// caller verified the factor method ("totp", "passkey" or
// "recovery_code"; the last opens a recovery session). It consumes the
// pending sign-in exactly once and returns the public continuation URL.
// The assurance never drops below the pending one.
func (f *Flow) CompletePending(w http.ResponseWriter, r *http.Request, userID int64, method string, assurance session.Assurance) (string, error) {
	p, err := f.pending().consume(r.Context(), f.binding(r))
	if err != nil {
		return "", err
	}
	if p.UserID != userID {
		return "", errPending
	}
	if assurance.Rank() > p.Assurance.Rank() {
		p.Assurance = assurance
	}
	if err := f.finalize(r.Context(), w, p, []string{p.PrimaryMethod, method}); err != nil {
		return "", err
	}
	return PublicContinuation(f.Root, p.Continuation), nil
}

// DiscardPending drops this browser's pending sign-in, for a factor that
// gave up after too many failures; msgs are shown on the sign-in page.
func (f *Flow) DiscardPending(r *http.Request, msgs ...Flash) {
	if err := f.pending().cancel(r.Context(), f.binding(r)); err != nil {
		f.logger().WarnContext(r.Context(), "pending sign-in not discarded", "error", err)
	}
	f.AddFlash(r, msgs...)
}
