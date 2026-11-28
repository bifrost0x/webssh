package auth

import (
	"context"
	"net/http"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/session"
)

// SignInDirect opens a browser session for a sign-in that is complete in
// one step: a passkey proves possession and user verification without a
// password, so no second factor follows. A pending sign-in of the browser
// is dropped. The account must be eligible under its current generation;
// the session is never remembered and continues at the root, like the
// Python release.
//
// still confirms, after the generation was read, that the credential the
// caller verified still exists (nil when there is none to confirm). A
// factor reset deletes the credential and raises the generation in one
// transaction: committed before the check, still fails; committed after
// it, the session refuses the old generation.
func (f *Flow) SignInDirect(w http.ResponseWriter, r *http.Request, userID int64, method string, assurance Assurance, still func(context.Context) error) error {
	ctx := r.Context()
	if err := f.pending().cancel(ctx, f.binding(r)); err != nil {
		f.logger().WarnContext(ctx, "pending sign-in not discarded", "error", err)
	}
	acc, err := f.Accounts.Get(ctx, userID)
	if fault.Is(err, fault.NotFound) {
		return fault.New(fault.AuthenticationNeeded, "")
	}
	if err != nil {
		return err
	}
	if still != nil {
		if err := still(ctx); err != nil {
			return err
		}
	}
	p := Pending{UserID: userID, Generation: acc.AuthGeneration, PrimaryMethod: method,
		Assurance: session.Assurance(assurance), Continuation: "/"}
	if err := f.finalize(ctx, w, p, []string{method}); err != nil {
		return err
	}
	return nil
}
