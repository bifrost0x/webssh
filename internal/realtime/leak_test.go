package realtime

import (
	"context"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
)

// Every way a connection ends releases all its goroutines: client close,
// revocation, protocol violation, slow consumer, shutdown with handlers
// still running.
func TestNoGoroutineLeakOnClose(t *testing.T) {
	base := settledGoroutines(t, 0)
	release := make(chan struct{})
	var closed atomic.Int32
	e := newEnv(t, Config{RecheckInterval: 20 * time.Millisecond, PingInterval: 30 * time.Millisecond}, func(s *Server) {
		testRoutes(new(atomic.Int32), release)(s)
		s.OnClose(func(protocol.Peer) { closed.Add(1) })
	})

	byClient := e.open(1, "a")
	_ = byClient.ws.Close(websocket.StatusNormalClosure, "")

	revoked := e.open(1, "b")
	revoked.write(`{"v":1,"t":"test.slow","id":"1"}`) // handler blocks until revoked
	e.sessions.revoke(1, "b", principal.ReasonLogout)
	revoked.closeStatus()

	violator := e.open(2, "c")
	violator.write("not json")
	violator.closeStatus()

	dropped := e.open(3, "d")
	_ = dropped.ws.CloseNow() // no close handshake at all

	for i := range 5 {
		c := e.open(4, "e"+string(rune('0'+i)))
		c.write(`{"v":1,"t":"test.slow","id":"2"}`) // still running at shutdown
	}
	waitFor(t, func() bool { return e.srv.Stats().Conns == 5 })

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	if err := e.srv.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	if got := closed.Load(); got != 9 {
		t.Fatalf("OnClose ran %d times, want 9", got)
	}
	e.ts.Close()
	close(release)
	settledGoroutines(t, base)
}

// settledGoroutines waits until the goroutine count is at most want (0:
// until it stops changing) and returns it.
func settledGoroutines(t *testing.T, want int) int {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	last := -1
	for {
		runtime.GC()
		n := runtime.NumGoroutine()
		if (want > 0 && n <= want) || (want == 0 && n == last) {
			return n
		}
		if time.Now().After(deadline) {
			buf := make([]byte, 1<<20)
			t.Fatalf("goroutines: %d, want at most %d\n%s", n, want, buf[:runtime.Stack(buf, true)])
		}
		last = n
		time.Sleep(50 * time.Millisecond)
	}
}
