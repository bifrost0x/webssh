package realtime

import (
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/realtime/protocol"
)

// The administration lists open connections by the id the page got in
// hello and ends exactly one of them with a final close.
func TestAdminConnections(t *testing.T) {
	e := newEnv(t, Config{MaxConns: 3, MaxConnsPerUser: 2}, nil)
	a := e.open(1, "s1")
	b := e.open(2, "s2")
	if len(a.hello.ConnectionID) != 20 || a.hello.ConnectionID == b.hello.ConnectionID {
		t.Fatalf("connection ids %q %q", a.hello.ConnectionID, b.hello.ConnectionID)
	}
	open := e.srv.OpenConnections()
	if len(open) != 2 || open[0].ID != a.hello.ConnectionID || open[0].UserID != 1 || open[1].UserID != 2 {
		t.Fatalf("open %+v", open)
	}
	if e.srv.DisconnectConnection("unknown") {
		t.Fatal("unknown id disconnected")
	}
	if !e.srv.DisconnectConnection(b.hello.ConnectionID) {
		t.Fatal("disconnect reported gone")
	}
	if code, reason := b.closeStatus(); code != protocol.CloseUnauthenticated || reason != closeAdminDisconnect {
		t.Fatalf("close %d %q", code, reason)
	}
	deadline := time.Now().Add(5 * time.Second)
	for len(e.srv.OpenConnections()) != 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if open := e.srv.OpenConnections(); len(open) != 1 || open[0].UserID != 1 {
		t.Fatalf("after disconnect %+v", open)
	}
	e.open(1, "s3")
	if _, err := e.tryOpen(1, "s4"); err == nil {
		t.Fatal("third connection of user 1 opened")
	}
	if c := e.srv.Capacity(); c.Max != 3 || c.MaxPerUser != 2 || c.RefusedPerUser != 1 || c.RefusedServer != 0 {
		t.Fatalf("capacity %+v", c)
	}
}
