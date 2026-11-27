package realtime

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/realtime/protocol"
)

// CloseAll closes every connection with 4503 and the reason, and the
// server keeps accepting new connections afterwards (unlike Shutdown).
func TestCloseAllKeepsAccepting(t *testing.T) {
	e := newEnv(t, Config{RecheckInterval: time.Hour}, testRoutes(new(atomic.Int32), nil))
	a, b := e.open(1, "s1"), e.open(2, "s2")
	if n := e.srv.CloseAll("maintenance"); n != 2 {
		t.Fatalf("closed %d connections, want 2", n)
	}
	for i, c := range []*client{a, b} {
		code, reason := c.closeStatus()
		if code != protocol.CloseMaintenance || reason != "maintenance" {
			t.Fatalf("connection %d: close %d %q", i, code, reason)
		}
	}
	waitFor(t, func() bool { return e.srv.Stats().Conns == 0 })
	c := e.open(1, "s3")
	if r := c.request(`{"v":1,"t":"test.echo","id":"e","p":{}}`); !r.OK {
		t.Fatalf("new connection after CloseAll: %+v", r)
	}
	if n := e.srv.CloseAll("again"); n != 1 {
		t.Fatalf("closed %d connections, want 1", n)
	}
}
