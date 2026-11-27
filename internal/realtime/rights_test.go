package realtime

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
)

// RS8-R01: a demotion closes the administrator connections of the account
// at once with the reconnect code; its other connections and other
// accounts stay.
func TestRightsChangedReconnectsAdministratorConnections(t *testing.T) {
	e := newEnv(t, Config{RecheckInterval: time.Hour}, testRoutes(new(atomic.Int32), nil))
	admin := principal.Principal{UserID: 1, SessionID: "s1", Username: "root", IsAdmin: true}
	e.sessions.set("tok-admin", admin)
	victim := e.openToken("tok-admin")
	plain := e.open(1, "s2")
	other := e.open(2, "s3")

	start := time.Now()
	if n := e.srv.RightsChanged(1); n != 1 {
		t.Fatalf("closed %d connections, want 1", n)
	}
	code, reason := victim.closeStatus()
	if code != protocol.CloseRightsChanged || reason != string(principal.ReasonRoleChanged) {
		t.Fatalf("close %d %q", code, reason)
	}
	if d := time.Since(start); d > revocationDeadline {
		t.Fatalf("took %v", d)
	}
	for _, c := range []*client{plain, other} {
		if r := c.request(`{"v":1,"t":"test.echo","id":"e","p":{}}`); !r.OK {
			t.Fatalf("unrelated connection affected: %+v", r)
		}
	}
}

// A mutating request of a connection whose account lost its
// administrator rights does not run; the connection closes with the
// reconnect code, not as an ended session. The periodic re-check does the
// same.
func TestLostRightsAreCheckedBeforeMutatingRequests(t *testing.T) {
	var ran atomic.Int32
	e := newEnv(t, Config{RecheckInterval: time.Hour}, testRoutes(&ran, nil))
	e.sessions.set("tok-admin", principal.Principal{UserID: 1, SessionID: "s1", Username: "root", IsAdmin: true})
	c := e.openToken("tok-admin")
	e.sessions.demote(1)
	c.write(`{"v":1,"t":"test.mutate","id":"m"}`)
	if code, reason := c.closeStatus(); code != protocol.CloseRightsChanged || reason != "role_changed" {
		t.Fatalf("close %d %q", code, reason)
	}
	if ran.Load() != 0 {
		t.Fatal("the mutating handler ran with lost administrator rights")
	}

	r := newEnv(t, Config{RecheckInterval: 50 * time.Millisecond}, nil)
	r.sessions.set("tok-admin", principal.Principal{UserID: 1, SessionID: "s1", Username: "root", IsAdmin: true})
	rc := r.openToken("tok-admin")
	r.sessions.demote(1)
	if code, _ := rc.closeStatus(); code != protocol.CloseRightsChanged {
		t.Fatalf("periodic re-check: close %d", code)
	}
}
