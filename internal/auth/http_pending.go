package auth

import (
	"net/http"

	"github.com/bifrost0x/webssh/internal/session"
)

// restartMessage is the notice of a pending sign-in that a factor gave up
// on, with the Python wording (totp_routes.py).
const restartMessage = "Too many invalid codes. Sign in again."

// SignIn returns the pending sign-in of this flow as the factor routes
// consume it (PendingSignIn). The flow keeps the primary method of a
// pending sign-in, so the adapter lives next to it.
func (f *Flow) SignIn() PendingSignIn { return flowSignIn{f} }

type flowSignIn struct{ f *Flow }

func (s flowSignIn) Pending(r *http.Request) (PendingLogin, error) {
	p, err := s.f.pending().peek(r.Context(), s.f.binding(r))
	if err != nil {
		return PendingLogin{}, err
	}
	return PendingLogin{UserID: p.UserID, PrimaryMethod: p.PrimaryMethod}, nil
}

func (s flowSignIn) Complete(w http.ResponseWriter, r *http.Request, userID int64, factor string, assurance Assurance) (string, error) {
	return s.f.CompletePending(w, r, userID, factor, session.Assurance(assurance))
}

// Discard drops the pending sign-in. Like the Python release it leaves
// the one-shot hint for the password form: the source and the name the
// user signed in with, so the form is filled again.
func (s flowSignIn) Discard(_ http.ResponseWriter, r *http.Request) error {
	msgs := []Flash{{Category: "error", Message: restartMessage}}
	if p, err := s.f.pending().peek(r.Context(), s.f.binding(r)); err == nil && p.PrimaryMethod == "password" && s.f.Accounts != nil {
		if acc, err := s.f.Accounts.Get(r.Context(), p.UserID); err == nil {
			msgs = append(msgs, Flash{Category: "login_auth_source", Message: "local"}, Flash{Category: "login_username", Message: acc.Username})
		}
	}
	s.f.DiscardPending(r, msgs...)
	return nil
}
