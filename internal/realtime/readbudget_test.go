package realtime

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/bifrost0x/webssh/internal/realtime/protocol"
)

type bigReq struct {
	Text string `json:"text"`
}

// A message above ReadLimit needs a reservation from the account's share
// and from the global budget, held until its handler returned. Without
// one the connection is closed with 1013, so neither one account nor all
// of them can make the server hold large messages without bound; a
// large message to a type with a small limit gives its reservation back
// at once.
func TestLargeMessagesNeedTheReadBudget(t *testing.T) {
	hold := make(chan struct{})
	mount := func(s *Server) {
		s.Mount(protocol.Handle("test.big", protocol.Spec{MaxPayload: 64 << 10, Async: true},
			func(ctx context.Context, _ protocol.Peer, r bigReq) (bigReq, error) {
				select {
				case <-hold:
				case <-ctx.Done():
				}
				return bigReq{Text: fmt.Sprint(len(r.Text))}, nil
			}))
	}
	limit := int64(64<<10 + envelopeOverhead)
	e := newEnv(t, Config{ReadLimit: 1024, ReadBudget: 3 * limit}, mount)
	n := limit - 1024 // what a large message reserves beyond ReadLimit
	e.srv.readWait = 100 * time.Millisecond
	big := `{"v":1,"t":"test.big","id":"b","p":{"text":"` + strings.Repeat("a", 40<<10) + `"}}`

	a1, a2, a3 := e.open(1, "a1"), e.open(1, "a2"), e.open(1, "a3")
	a1.write(big)
	a2.write(big)
	waitFor(t, func() bool { return e.srv.reads.used(1) == 2*n })
	a3.write(big)
	if code, _ := a3.closeStatus(); code != websocket.StatusTryAgainLater {
		t.Fatalf("third large message of one account: close %d, want 1013", code)
	}
	b1 := e.open(2, "b1")
	b1.write(big)
	waitFor(t, func() bool { return e.srv.reads.used(2) == n })
	c1 := e.open(3, "c1")
	c1.write(big)
	if code, _ := c1.closeStatus(); code != websocket.StatusTryAgainLater {
		t.Fatalf("large message over the global budget: close %d, want 1013", code)
	}

	close(hold)
	for _, c := range []*client{a1, a2, b1} {
		if env := c.read(); env.T != protocol.TypeResult {
			t.Fatalf("got %q, want the result", env.T)
		}
	}
	waitFor(t, func() bool { return e.srv.reads.used(1)+e.srv.reads.used(2) == 0 })

	// An oversized message to a small type is refused and its
	// reservation returned before the next message is read.
	d := e.open(4, "d1")
	if r := d.request(`{"v":1,"t":"session.keepalive","id":"k","p":{"x":"` + strings.Repeat("a", 40<<10) + `"}}`); r.OK {
		t.Fatal("an oversized keepalive was accepted")
	}
	if n := e.srv.reads.used(4); n != 0 {
		t.Fatalf("%d bytes stay reserved after the refusal", n)
	}
	if r := d.request(`{"v":1,"t":"session.keepalive","id":"k2"}`); !r.OK {
		t.Fatalf("keepalive after the refusal: %+v", r)
	}
}
