package realtime

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// TestAutobahnEcho serves an echo endpoint with the production library
// configuration (acceptOptions, DefaultReadLimit, bounded close) for the
// Autobahn fuzzing client. It runs only when WEBSSH_AUTOBAHN_ADDR is set,
// for WEBSSH_AUTOBAHN_SECONDS (default 600); the suite itself runs in a
// container (see the F4 report).
func TestAutobahnEcho(t *testing.T) {
	addr := os.Getenv("WEBSSH_AUTOBAHN_ADDR")
	if addr == "" {
		t.Skip("set WEBSSH_AUTOBAHN_ADDR to serve the Autobahn echo endpoint")
	}
	seconds := 600
	if v := os.Getenv("WEBSSH_AUTOBAHN_SECONDS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			t.Fatalf("WEBSSH_AUTOBAHN_SECONDS=%q", v)
		}
		seconds = n
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{
		ReadHeaderTimeout: 5 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ws, raw, err := upgrade(w, r, nil)
			if err != nil {
				return
			}
			ws.SetReadLimit(DefaultReadLimit)
			ctx := context.WithoutCancel(r.Context())
			for {
				typ, data, err := ws.Read(ctx)
				if err != nil {
					closeBounded(ws, raw, websocket.StatusNormalClosure, "")
					return
				}
				wctx, cancel := context.WithTimeout(ctx, DefaultWriteTimeout)
				err = ws.Write(wctx, typ, data)
				cancel()
				if err != nil {
					return
				}
			}
		}),
	}
	go func() {
		time.Sleep(time.Duration(seconds) * time.Second)
		_ = srv.Close()
	}()
	if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		t.Fatal(err)
	}
}
