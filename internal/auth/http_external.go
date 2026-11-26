package auth

import (
	"net/http"
	"slices"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/session"
)

// ExternalSignIn is a sign-in a redirect provider vouched for.
type ExternalSignIn struct {
	UserID int64
	// Method is the provider's method name ("oidc", "github").
	Method    string
	Assurance Assurance
	// StrongAt is when the provider authenticated the user with MFA or
	// a phishing-resistant method (the OIDC auth_time); zero otherwise.
	StrongAt time.Time
	// Continuation is the local path to return to.
	Continuation string
}

// errNoLocalFactor is the refusal of oidc_routes.py when MFA is required
// and the account has no factor the provider sign-in may finish with.
var errNoLocalFactor = fault.New(fault.Forbidden, "No active local MFA factor is available")

// SignInExternal finishes a provider sign-in like the Python callback:
// an account that requires MFA and a provider answer at BASIC continue
// with a local second factor (recovery codes excluded) on the sign-in
// page; otherwise the browser session starts at once with the provider's
// assurance. It answers the request in both cases. A locked account or a
// changed auth generation fails at the session issue as for every
// sign-in.
func (f *Flow) SignInExternal(w http.ResponseWriter, r *http.Request, in ExternalSignIn) error {
	ctx := r.Context()
	acc, err := f.Accounts.Get(ctx, in.UserID)
	if fault.Is(err, fault.NotFound) {
		return fault.New(fault.AuthenticationNeeded, "")
	}
	if err != nil {
		return err
	}
	if acc.IsLocked {
		return fault.New(fault.Forbidden, "External identity is not linked to an active account")
	}
	p := Pending{UserID: in.UserID, Generation: acc.AuthGeneration, PrimaryMethod: in.Method,
		Assurance: session.Assurance(in.Assurance), Continuation: SafeContinuation(in.Continuation)}
	if in.Assurance != AssuranceBasic {
		p.StrongAt = in.StrongAt
	}
	if acc.MFARequired && in.Assurance == AssuranceBasic {
		methods := slices.DeleteFunc(f.methods(ctx, in.UserID), func(m string) bool { return m == "recovery" })
		if len(methods) == 0 {
			return errNoLocalFactor
		}
		if err := f.pending().begin(ctx, f.binding(r), p); err != nil {
			return err
		}
		f.Pages.Login(w, r, http.StatusOK, LoginView{AuthSource: in.Method, MFARequired: true, MFAMethods: methods})
		return nil
	}
	if err := f.pending().cancel(ctx, f.binding(r)); err != nil {
		f.logger().WarnContext(ctx, "pending sign-in not discarded", "error", err)
	}
	if err := f.finalize(ctx, w, p, []string{in.Method}); err != nil {
		return err
	}
	f.redirect(w, r, PublicContinuation(f.Root, p.Continuation))
	return nil
}
