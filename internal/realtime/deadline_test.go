package realtime

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// The HTTP edge sets a read and write deadline on every request before it
// routes it. They must not survive the upgrade (net/http clears them on
// Hijack); otherwise every WebSocket would end with the request deadline.
func TestUpgradeLiftsTheRequestDeadlines(t *testing.T) {
	e := newEnv(t, Config{}, nil)
	edge := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rc := http.NewResponseController(w)
		_ = rc.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		_ = rc.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
		e.srv.ServeHTTP(w, r)
	})
	e.ts.Close()
	e.ts = httptest.NewServer(edge)
	c := e.open(1, "s1")
	time.Sleep(300 * time.Millisecond)
	if r := c.request(`{"v":1,"t":"session.keepalive","id":"k"}`); !r.OK {
		t.Fatalf("keepalive after the request deadline: %+v", r)
	}
}
