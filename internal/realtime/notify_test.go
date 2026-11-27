package realtime

import (
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/realtime/protocol"
)

// NotifyUser reaches every connection of the account, in every browser
// session, and no connection of another account.
func TestNotifyUserReachesOnlyTheAccount(t *testing.T) {
	e := newEnv(t, Config{}, nil)
	first, second := e.open(1, "a"), e.open(1, "b")
	other := e.open(2, "c")
	deadline := time.Now().Add(5 * time.Second)
	for e.srv.sessions.all() == nil || len(e.srv.sessions.all()) < 3 {
		if time.Now().After(deadline) {
			t.Fatal("connections not registered")
		}
		time.Sleep(time.Millisecond)
	}
	if n := e.srv.NotifyUser(1, protocol.TypeDiscoveryMaintenance, protocol.DiscoveryMaintenance{ProfileID: "p"}); n != 2 {
		t.Fatalf("sent to %d connections, want 2", n)
	}
	for _, c := range []*client{first, second} {
		if env := c.read(); env.T != protocol.TypeDiscoveryMaintenance || string(env.P) != `{"profile_id":"p"}` {
			t.Fatalf("event %s %s", env.T, env.P)
		}
	}
	// The other account gets the next event of its own, not this one.
	e.srv.NotifyUser(2, protocol.TypeDiscoveryPlatform, protocol.DiscoveryPlatform{ProfileID: "q"})
	if env := other.read(); env.T != protocol.TypeDiscoveryPlatform {
		t.Fatalf("other account got %s", env.T)
	}
	if n := e.srv.NotifyUser(3, protocol.TypeDiscoveryPlatform, protocol.DiscoveryPlatform{ProfileID: "q"}); n != 0 {
		t.Fatalf("sent to %d connections of an account without any", n)
	}
}
