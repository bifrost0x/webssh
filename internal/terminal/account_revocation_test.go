package terminal

import (
	"testing"

	"github.com/bifrost0x/webssh/internal/principal"
)

// An account-wide revocation (no browser session left, SessionID empty) of
// a lock, deletion or MFA reset ends the account's live terminals and
// removes its detached tmux sessions, as revoke_user_access did.
func TestAccountWideRevocationEndsDetachedTmux(t *testing.T) {
	for _, reason := range []principal.Reason{principal.ReasonAccountLocked, principal.ReasonFactorChanged} {
		t.Run(string(reason), func(t *testing.T) {
			r := newTmuxRig(t)
			r.seed(t, detachedRow("detached", "webssh_detached"))
			res := openTmux(t, r, user(t, 1), tmuxOpen(1, "r1", ""))
			r.m.Revoked(principal.Revocation{UserID: 1, Reason: reason})
			h := r.host(t, 0)
			eventually(t, "connection closed", func() bool { h.mu.Lock(); defer h.mu.Unlock(); return h.closed == 1 })
			if !h.ranAny("kill-session -t '=" + res.Info.TmuxSessionName + "'") {
				t.Fatalf("live tmux session not ended: %q", h.ran())
			}
			eventually(t, "rows removed", func() bool { return len(r.rows(t, 1)) == 0 })
		})
	}
}
