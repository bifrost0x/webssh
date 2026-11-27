package client

import (
	"context"
	"testing"

	"github.com/bifrost0x/webssh/internal/fault"
)

type guard struct{ err error }

func (g *guard) Check(context.Context) error { return g.err }

// A saved password whose assignment changed while the attempt waited is
// never sent: the guard's refusal ends the attempt with its own code.
func TestGuardRefusalSendsNoPassword(t *testing.T) {
	calls := 0
	s := startServer(t, passwordServer("u", "pw", &calls))
	d, _ := newDialer(trusting(s), nil)
	refused := &guard{err: fault.New(fault.CredentialTargetChanged, "")}
	_, err := d.Dial(t.Context(), target(s, "u", Auth{Password: "pw", Guard: refused}), nil)
	if fault.CodeOf(err) != fault.CredentialTargetChanged {
		t.Fatalf("err = %v", err)
	}
	if calls != 0 {
		t.Fatalf("password sent %d times after the guard refused", calls)
	}
	c, err := d.Dial(t.Context(), target(s, "u", Auth{Password: "pw", Guard: &guard{}}), nil)
	if err != nil {
		t.Fatalf("guard that passes: %v", err)
	}
	_ = c.Close()
}
