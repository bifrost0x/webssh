package auth

import (
	"context"
	"net/http"
	"slices"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/session"
	"github.com/bifrost0x/webssh/internal/store"
)

// errNoLocalFactor refuses an external sign-in of an account that
// requires a second factor but has none it can use here.
var errNoLocalFactor = fault.New(fault.Forbidden, "No active local MFA factor is available")

// SignInExternal finishes the sign-in of an account a redirect provider
// vouched for (method "github" or "oidc"). A pending sign-in of the
// browser is replaced. An account that requires a second factor gets the
// factor step of the sign-in page, without recovery codes, which only a
// password sign-in may use; one without such a factor is
// fault.Forbidden and nothing is written. Otherwise the session is issued
// (never remembered) and the browser continues at continuation. On success
// the response has been written.
func (f *Flow) SignInExternal(w http.ResponseWriter, r *http.Request, userID int64, method, continuation string) error {
	ctx := r.Context()
	acc, err := f.Accounts.Get(ctx, userID)
	if fault.Is(err, fault.NotFound) {
		return fault.New(fault.AuthenticationNeeded, "")
	}
	if err != nil {
		return err
	}
	p := Pending{UserID: userID, Generation: acc.AuthGeneration, PrimaryMethod: method, Assurance: session.Basic,
		Continuation: SafeContinuation(continuation)}
	if acc.MFARequired {
		methods := slices.DeleteFunc(f.methods(ctx, userID), func(m string) bool { return m == "recovery" })
		if len(methods) == 0 {
			return errNoLocalFactor
		}
		if err := f.pending().begin(ctx, f.binding(r), p); err != nil {
			return err
		}
		f.Pages.Login(w, r, http.StatusOK, LoginView{AuthSource: method, MFARequired: true, MFAMethods: methods})
		return nil
	}
	if err := f.pending().cancel(ctx, f.binding(r)); err != nil {
		f.logger().WarnContext(ctx, "pending sign-in not discarded", "error", err)
	}
	if err := f.finalize(ctx, w, p, []string{method}); err != nil {
		return err
	}
	f.redirect(w, r, PublicContinuation(f.Root, p.Continuation))
	return nil
}

// RenewAfter runs change and, in the same transaction, raises the
// account's generation, ends every session of the account for reason and
// moves this browser to a new session with the sign-in's methods,
// assurance and expiry (invalidate_user_authentication with
// preserve_current_browser). An error of change is returned as it is and
// nothing is stored; a session that ended meanwhile is
// fault.AuthenticationNeeded.
func (f *Flow) RenewAfter(w http.ResponseWriter, r *http.Request, reason principal.Reason, change func(ctx context.Context, tx *store.Tx) error) error {
	ctx := r.Context()
	p, err := principal.Require(ctx)
	if err != nil {
		return err
	}
	cur, err := f.Sessions.Lookup(ctx, p.SessionID)
	if err != nil {
		return err
	}
	var revs []principal.Revocation
	var fresh session.Session
	var token string
	err = f.DB.Write(ctx, func(tx *store.Tx) error {
		if err := change(ctx, tx); err != nil {
			return err
		}
		gen, err := f.Accounts.RaiseGenerationTx(ctx, tx, p.UserID)
		if err != nil {
			return err
		}
		if revs, err = f.Sessions.RevokeUserTx(ctx, tx, p.UserID, reason, ""); err != nil {
			return err
		}
		if !slices.ContainsFunc(revs, func(r principal.Revocation) bool { return r.SessionID == p.SessionID }) {
			return errSessionGone
		}
		fresh, token, err = f.Sessions.IssueTx(ctx, tx, session.IssueRequest{
			UserID: p.UserID, Generation: gen, PrimaryMethod: cur.PrimaryMethod, Methods: cur.Methods,
			Assurance: cur.Assurance, Remember: cur.Remember, StrongAt: cur.StrongAt, ExpiresAt: cur.ExpiresAt,
		})
		return err
	})
	if err != nil {
		return err
	}
	f.Sessions.Publish(revs)
	var expires time.Time
	if fresh.Remember {
		expires = fresh.ExpiresAt
	}
	f.Cookie.Set(w, token, expires)
	return nil
}
