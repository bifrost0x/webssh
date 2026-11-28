package webauthn

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/bifrost0x/webssh/internal/auth"
	"github.com/bifrost0x/webssh/internal/fault"
)

var errTooMany = fault.New(fault.RateLimited, "Too many login attempts")

// pendingUser returns the account of the browser's pending sign-in, or 0
// for a sign-in without a user name.
func (h *HTTP) pendingUser(r *http.Request) int64 {
	if h.Pending == nil {
		return 0
	}
	p, err := h.Pending.Pending(r)
	if err != nil {
		return 0
	}
	return p.UserID
}

func (h *HTTP) binding(r *http.Request) string {
	if h.Binding == nil {
		return ""
	}
	return h.Binding(r)
}

// signInOptions starts a passkey sign-in: for the pending sign-in of this
// browser if there is one, otherwise without a user name.
func (h *HTTP) signInOptions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if h.Limits.SourceLimited(r, "webauthn_auth_options") {
		h.audit().Security(ctx, slog.LevelWarn, "RATE_LIMIT_EXCEEDED", "endpoint", "webauthn_auth_options")
		h.fail(w, r, errTooMany)
		return
	}
	options, err := h.Service.SignInOptions(ctx, h.binding(r), h.pendingUser(r))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	auth.WriteJSON(w, http.StatusOK, options)
}

// signIn verifies the assertion. It completes the pending sign-in of this
// browser with the passkey, or signs in the account the passkey belongs
// to. Every refusal is the same 401.
func (h *HTTP) signIn(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if h.Limits.SourceLimited(r, "webauthn_auth_verify") {
		h.fail(w, r, errTooMany)
		return
	}
	body := auth.ReadObject(w, r)
	pending := h.pendingUser(r)
	userID, passkeyID, err := h.Service.SignInPasskey(ctx, h.binding(r), pending, body["credential"])
	if err == nil {
		if pending != 0 {
			var continuation string
			continuation, err = h.Pending.Complete(w, r, userID, "passkey", auth.AssurancePhishingResistant)
			if err == nil {
				auth.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "continuation": continuation})
				return
			}
		} else if err = h.SignIn.SignInDirect(w, r, userID, "passkey", auth.AssurancePhishingResistant, h.stillOwned(userID, passkeyID)); err == nil {
			auth.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
			return
		}
	}
	fields := []any{"reason", Reason(err)}
	if userID != 0 {
		fields = append(fields, "user_id", userID)
	} else if pending != 0 {
		fields = append(fields, "user_id", pending)
	}
	h.audit().Security(ctx, slog.LevelWarn, "WEBAUTHN_AUTHENTICATION_REJECTED", fields...)
	if fe, ok := fault.From(err); ok && (fe.Code == fault.StorageError || fe.Code == fault.Internal) {
		h.fail(w, r, err)
		return
	}
	h.fail(w, r, ErrAssertion)
}

// isoformat renders t as Python's datetime.isoformat() of the naive UTC
// value the Python release returned.
func isoformat(t time.Time) string {
	t = t.UTC()
	if t.Nanosecond()/1000 == 0 {
		return t.Format("2006-01-02T15:04:05")
	}
	return t.Format("2006-01-02T15:04:05.000000")
}

// stillOwned confirms at issue that the passkey that signed is still the
// account's: an MFA reset or a deletion after the assertion ends the
// sign-in.
func (h *HTTP) stillOwned(userID, passkeyID int64) func(context.Context) error {
	return func(ctx context.Context) error {
		ok, err := h.Service.Owned(ctx, userID, passkeyID)
		if err != nil {
			return err
		}
		if !ok {
			return fault.Wrap(fault.AuthenticationNeeded, errors.New("passkey removed during the sign-in"), "Passkey authentication failed")
		}
		return nil
	}
}
