package httpapi

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// A request that announces a body the edge never reads is answered at
// once and the connection is closed. Before, net/http tried to discard
// the unread body before the answer, and on routes the edge answers
// itself (no route, wrong method, /socket.io, /ws) without any read
// deadline, so a client that never sent the body held the connection
// and its listener slot without end.
func TestUnreadAnnouncedBodyIsAnsweredAtOnce(t *testing.T) {
	e := newEdge(t)
	e.h.Mux().HandleFunc("GET /login", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("page")) })
	srv := httptest.NewUnstartedServer(e.h)
	ConfigureServer(srv.Config)
	srv.Start()
	defer srv.Close()
	addr := srv.Listener.Addr().String()

	cases := []string{
		"GET /no-such-route",            // no route
		"POST /health",                  // wrong method
		"GET /socket.io/",               // AccessGone
		"GET /ws",                       // AccessUpgrade
		"GET /login",                    // a handler that ignores the body
		"POST /api/account/preferences", // refused before the body: no session
	}
	got := make([]string, len(cases))
	var wg sync.WaitGroup
	for i, line := range cases {
		wg.Go(func() {
			c, err := net.Dial("tcp", addr)
			if err != nil {
				got[i] = err.Error()
				return
			}
			defer c.Close()
			fmt.Fprintf(c, "%s HTTP/1.1\r\nHost: %s\r\nAccept: application/json\r\nContent-Length: 1000\r\n\r\n", line, addr)
			_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
			resp, err := http.ReadResponse(bufio.NewReader(c), nil)
			if err != nil {
				got[i] = "no answer: " + err.Error()
				return
			}
			resp.Body.Close()
			got[i] = fmt.Sprintf("%d close=%v", resp.StatusCode, resp.Close)
		})
	}
	wg.Wait()
	for i, line := range cases {
		if !strings.HasSuffix(got[i], "close=true") {
			t.Errorf("%s with an unsent body: %s, want an answer with Connection: close", line, got[i])
		}
	}
}

// deadlineRecorder records the deadlines the edge sets through
// http.ResponseController.
type deadlineRecorder struct {
	*httptest.ResponseRecorder
	read, write time.Time
}

func (d *deadlineRecorder) SetReadDeadline(t time.Time) error  { d.read = t; return nil }
func (d *deadlineRecorder) SetWriteDeadline(t time.Time) error { d.write = t; return nil }

// Every request gets the read and write deadline, also on the routes the
// edge answers before the session (no route, wrong method, /socket.io,
// /ws, the closed admin panel).
func TestEveryRequestHasTheDeadlines(t *testing.T) {
	e := newEdge(t)
	for _, target := range []string{"/no-such-route", "/socket.io/", "/ws", "/health", "/login"} {
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			w := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
			e.h.ServeHTTP(w, httptest.NewRequest(method, "http://webssh.test"+target, nil))
			if w.read.IsZero() || w.write.IsZero() {
				t.Errorf("%s %s: read deadline %v, write deadline %v", method, target, w.read, w.write)
			}
		}
	}
}
