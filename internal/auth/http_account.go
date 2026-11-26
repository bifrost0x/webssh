package auth

import (
	"net/http"
	"strconv"
	"unicode/utf8"

	"github.com/bifrost0x/webssh/internal/accounts"
	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/session"
	"github.com/bifrost0x/webssh/internal/store"
)

func (f *Flow) registrationState(r *http.Request) (ongoing, bootstrap bool, err error) {
	if f.Settings != nil {
		if ongoing, err = f.Settings.RegistrationEnabled(r.Context()); err != nil {
			return false, false, err
		}
	}
	bootstrap, err = f.bootstrapOpen(r.Context())
	return ongoing, bootstrap, err
}

func (f *Flow) registerPage(w http.ResponseWriter, r *http.Request) {
	ongoing, bootstrap, err := f.registrationState(r)
	switch {
	case err != nil:
		f.fail(w, r, err)
	case !ongoing && !bootstrap:
		f.AddFlash(w, r, Flash{"error", msgRegistrationOff})
		f.redirect(w, r, f.url("/login"))
	case f.signedIn(r):
		f.redirect(w, r, f.url("/"))
	default:
		f.Cookies.Binding(w, r)
		f.Pages.Register(w, r, http.StatusOK, FormView{Flashes: f.TakeFlashes(r)})
	}
}

func (f *Flow) register(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ongoing, bootstrap, err := f.registrationState(r)
	switch {
	case err != nil:
		f.fail(w, r, err)
		return
	case !ongoing && !bootstrap:
		f.AddFlash(w, r, Flash{"error", msgRegistrationOff})
		f.redirect(w, r, f.url("/login"))
		return
	case f.signedIn(r):
		f.redirect(w, r, f.url("/"))
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	ip := f.clientIP(r)
	if f.Limits.Enabled {
		if ok, _ := f.Limiter.Allow("register:"+SourceBucket(ip, f.ipPrefix(ctx)), f.Limits.Default); !ok {
			if f.Audit != nil {
				f.Audit.RateLimitExceeded("register", ip, "")
			}
			f.Pages.Register(w, r, http.StatusOK, FormView{Flashes: []Flash{{"error", "Too many registration attempts. Please try again later."}}})
			return
		}
	}
	username, password := r.PostFormValue("username"), r.PostFormValue("password")
	if password != r.PostFormValue("confirm_password") {
		f.Pages.Register(w, r, http.StatusOK, FormView{Flashes: []Flash{{"error", "Passwords do not match"}}})
		return
	}
	acc, err := f.Accounts.Create(ctx, accounts.CreateRequest{Username: username, Password: password, FirstOnly: !ongoing})
	if err != nil {
		_, code, msg := fault.Status(err)
		if code != fault.InvalidValue && code != fault.Forbidden {
			f.fail(w, r, err)
			return
		}
		if f.Audit != nil {
			f.Audit.Registration(username, false, ip)
		}
		f.Pages.Register(w, r, http.StatusOK, FormView{Flashes: []Flash{{"error", msg}}})
		return
	}
	p := Pending{UserID: acc.ID, Generation: acc.AuthGeneration, PrimaryMethod: f.Password.Name(), Assurance: session.Basic, Continuation: "/"}
	binding, err := f.finalize(ctx, w, p, []string{p.PrimaryMethod})
	if err != nil {
		f.fail(w, r, err)
		return
	}
	if f.Audit != nil {
		f.Audit.Registration(username, true, ip)
	}
	f.flash.add(f.now(), binding, Flash{"success", "Account created successfully!"})
	f.redirect(w, r, f.url("/"))
}

// passwordAccount returns the signed-in local account; directory- and
// GitHub-managed accounts get 403 as in the Python release.
func (f *Flow) passwordAccount(w http.ResponseWriter, r *http.Request) (principal.Principal, accounts.Account, bool) {
	p, err := principal.Require(r.Context())
	if err != nil {
		if fault.Is(err, fault.AuthenticationNeeded) {
			f.redirect(w, r, f.url("/login"))
		} else {
			f.fail(w, r, err)
		}
		return p, accounts.Account{}, false
	}
	acc, err := f.Accounts.Get(r.Context(), p.UserID)
	if err == nil && acc.Managed != accounts.ManagedLocal {
		err = fault.New(fault.Forbidden, "")
	}
	if err != nil {
		f.fail(w, r, err)
		return p, accounts.Account{}, false
	}
	return p, acc, true
}

func (f *Flow) passwordPage(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := f.passwordAccount(w, r); ok {
		f.Pages.ChangePassword(w, r, http.StatusOK, FormView{Flashes: f.TakeFlashes(r)})
	}
}

// passwordProblem checks the change-password form in the Python order.
func (f *Flow) passwordProblem(r *http.Request, userID int64, current, next, confirm string) (string, error) {
	ok, err := f.Passwords.Matches(r.Context(), userID, current)
	switch {
	case err != nil:
		return "", err
	case !ok:
		return "Current password is incorrect", nil
	case next != confirm:
		return "New passwords do not match", nil
	case utf8.RuneCountInString(next) < 8:
		return "New password must be at least 8 characters", nil
	case f.Passwords.ValidateNew(next) != "":
		return "New password must not exceed 1024 bytes when encoded as UTF-8", nil
	case next == current:
		return "New password must be different from current password", nil
	}
	return "", nil
}

// changePassword stores the new password, raises the account's
// generation and ends every session of the account in one transaction;
// this browser continues with a new session that keeps the sign-in's
// methods, assurance and expiry (invalidate_user_authentication with
// preserve_current_browser).
func (f *Flow) changePassword(w http.ResponseWriter, r *http.Request) {
	p, acc, ok := f.passwordAccount(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	ip := f.clientIP(r)
	show := func(msg string) {
		f.Pages.ChangePassword(w, r, http.StatusOK, FormView{Flashes: []Flash{{"error", msg}}})
	}
	if f.Limits.Enabled {
		okIP, _ := f.Limiter.Allow("change_password:"+SourceBucket(ip, f.ipPrefix(ctx)), f.Limits.Login)
		okUser, _ := f.Limiter.Allow("change_password_account:user:"+strconv.FormatInt(p.UserID, 10), f.Limits.Login)
		okUserIP, _ := f.Limiter.Allow("change_password_account:ip:"+SourceBucket(ip, f.ipPrefix(ctx)), f.Limits.Login)
		if !okIP || !okUser || !okUserIP {
			if f.Audit != nil {
				f.Audit.RateLimitExceeded("change_password", ip, p.Username)
			}
			show("Too many attempts. Please try again later.")
			return
		}
	}
	current, next := r.PostFormValue("current_password"), r.PostFormValue("new_password")
	problem, err := f.passwordProblem(r, p.UserID, current, next, r.PostFormValue("confirm_password"))
	if err == nil && problem != "" {
		show(problem)
		return
	}
	var hash string
	if err == nil {
		hash, err = f.Passwords.Hash(ctx, next)
	}
	cur, err2 := f.Sessions.Lookup(ctx, p.SessionID)
	if err == nil {
		err = err2
	}
	if err != nil {
		f.fail(w, r, err)
		return
	}
	var revs []principal.Revocation
	var fresh session.Session
	var token string
	err = f.DB.Write(ctx, func(tx *store.Tx) error {
		if err := f.Passwords.StoreTx(ctx, tx, p.UserID, hash); err != nil {
			return err
		}
		gen, err := f.Accounts.PasswordChangedTx(ctx, tx, p.UserID, hash)
		if err != nil {
			return err
		}
		if revs, err = f.Sessions.RevokeUserTx(ctx, tx, p.UserID, principal.ReasonPasswordChanged, ""); err != nil {
			return err
		}
		fresh, token, err = f.Sessions.IssueTx(ctx, tx, session.IssueRequest{
			UserID: p.UserID, Generation: gen, PrimaryMethod: cur.PrimaryMethod, Methods: cur.Methods,
			Assurance: cur.Assurance, Remember: cur.Remember, StrongAt: cur.StrongAt, ExpiresAt: cur.ExpiresAt,
		})
		return err
	})
	if err != nil {
		f.Cookies.Clear(w)
		f.logger().WarnContext(ctx, "Password change session rotation failed", "user", acc.Username, "error", err)
		f.fail(w, r, fault.Wrap(fault.StorageError, err, ""))
		return
	}
	f.Sessions.Publish(revs)
	f.Cookies.Set(w, token, fresh)
	if f.Audit != nil {
		f.Audit.PasswordChange(acc.Username, true, ip)
	}
	f.AddFlash(w, r, Flash{"success", "Password updated successfully"})
	f.redirect(w, r, f.url("/"))
}
