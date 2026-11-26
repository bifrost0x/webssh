package stepup

import (
	"slices"
	"testing"

	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/principal/principaltest"
)

func TestEveryActionHasOneAudience(t *testing.T) {
	t.Parallel()
	for _, a := range principal.Actions() {
		n := 0
		for _, list := range [][]principal.Action{adminActions, selfActions, accountActions} {
			if slices.Contains(list, a) {
				n++
			}
		}
		if n != 1 {
			t.Errorf("action %q is in %d audiences, want exactly 1", a, n)
		}
	}
	for _, list := range [][]principal.Action{adminActions, selfActions, accountActions} {
		for _, a := range list {
			if !a.Known() {
				t.Errorf("audience lists %q, which is not in the catalog", a)
			}
		}
	}
}

// A user who is not an administrator gets no intent for an admin action,
// whatever the target.
func TestAdminActionsRefuseUsers(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	p := principaltest.User(7)
	for _, a := range adminActions {
		if _, err := e.svc.Begin(t.Context(), p, a, "global", ChannelAdmin); err == nil {
			t.Errorf("%s: a user got a step-up intent", a)
		}
	}
}
