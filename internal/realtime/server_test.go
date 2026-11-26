package realtime

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
)

func TestNewServerRequiresDeps(t *testing.T) {
	s := newFakeSessions()
	full := Deps{Origin: &OriginPolicy{}, Sessions: s, Revocations: &s.feed, Log: discardLog()}
	for name, d := range map[string]Deps{
		"origin":      {Sessions: s, Revocations: &s.feed, Log: discardLog()},
		"sessions":    {Origin: &OriginPolicy{}, Revocations: &s.feed, Log: discardLog()},
		"revocations": {Origin: &OriginPolicy{}, Sessions: s, Log: discardLog()},
		"log":         {Origin: &OriginPolicy{}, Sessions: s, Revocations: &s.feed},
		"bad origin":  {Origin: &OriginPolicy{Allowed: []string{"*"}}, Sessions: s, Revocations: &s.feed, Log: discardLog()},
	} {
		if _, err := NewServer(Config{}, d); err == nil {
			t.Errorf("%s: NewServer accepted incomplete deps", name)
		}
	}
	if _, err := NewServer(Config{}, full); err != nil {
		t.Fatal(err)
	}
}

func TestUpgradeRefused(t *testing.T) {
	e := newEnv(t, Config{}, nil)
	ok := e.sessions.token(1, "s1")
	rec := e.sessions.token(2, "s2")
	p := principal.Principal{UserID: 2, SessionID: "s2", Recovery: true}
	e.sessions.set(rec, p)
	own := e.ts.URL
	cases := []struct {
		name, origin, cookie string
		status               int
	}{
		{"no origin", "", ok, http.StatusForbidden},
		{"foreign origin", "http://evil.example", ok, http.StatusForbidden},
		{"same host other port", "http://127.0.0.1:1", ok, http.StatusForbidden},
		{"https origin on plain listener", strings.Replace(own, "http://", "https://", 1), ok, http.StatusForbidden},
		{"null origin", "null", ok, http.StatusForbidden},
		{"no session", own, "", http.StatusUnauthorized},
		{"forged session", own, "forged", http.StatusUnauthorized},
		{"recovery session", own, rec, http.StatusForbidden},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			c, resp, err := e.dial(ctx, tt.origin, tt.cookie)
			if err == nil {
				_ = c.CloseNow()
				t.Fatal("upgrade accepted")
			}
			if resp == nil || resp.StatusCode != tt.status {
				t.Fatalf("status = %v, want %d", resp, tt.status)
			}
		})
	}
	t.Run("origin is checked before the session", func(t *testing.T) {
		before := e.sessions.checkCount()
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		if _, resp, _ := e.dial(ctx, "http://evil.example", "forged"); resp == nil || resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status %v", resp)
		}
		if e.sessions.checkCount() != before {
			t.Fatal("session checked for a foreign origin")
		}
	})
	t.Run("POST", func(t *testing.T) {
		resp, err := http.Post(e.ts.URL+"/ws", "text/plain", nil)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("status %d", resp.StatusCode)
		}
	})
}

func TestHello(t *testing.T) {
	e := newEnv(t, Config{}, func(s *Server) {
		s.SetRestorer(restorerFunc(func(_ context.Context, p principal.Principal) ([]protocol.SessionInfo, error) {
			return []protocol.SessionInfo{{SessionID: "t1", Host: "h", Port: 22, Username: p.Username, LastSeq: 7}}, nil
		}))
	})
	c := e.open(3, "s3")
	h := c.hello
	if h.Schema != protocol.Version || h.User.Username != "user3" || h.User.IsAdmin {
		t.Fatalf("hello = %+v", h)
	}
	if len(h.Restorable) != 1 || h.Restorable[0].SessionID != "t1" || h.Restorable[0].LastSeq != 7 {
		t.Fatalf("restorable = %+v", h.Restorable)
	}
	if got := c.ws.Subprotocol(); got != "webssh.v1" {
		t.Fatalf("subprotocol %q", got)
	}
}

type restorerFunc func(context.Context, principal.Principal) ([]protocol.SessionInfo, error)

func (f restorerFunc) Restorable(ctx context.Context, p principal.Principal) ([]protocol.SessionInfo, error) {
	return f(ctx, p)
}

func TestHelloWithoutRestorerHasEmptyList(t *testing.T) {
	e := newEnv(t, Config{}, nil)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	ws, _, err := e.dial(ctx, e.ts.URL, e.sessions.token(1, "s1"))
	if err != nil {
		t.Fatal(err)
	}
	defer ws.CloseNow()
	_, b, err := ws.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"restorable":[]`) {
		t.Fatalf("hello %s", b)
	}
}

func TestUnsupportedVersionClosesWith4001(t *testing.T) {
	e := newEnv(t, Config{}, nil)
	for _, offer := range [][]string{{"webssh.v99"}, {}, {"chat"}} {
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		ws, _, err := e.dial(ctx, e.ts.URL, e.sessions.token(1, "s1"), offer...)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		c := &client{t: t, ctx: ctx, ws: ws}
		code, reason := c.closeStatus()
		cancel()
		if code != protocol.CloseUnsupportedVersion || reason != "supported: webssh.v1" {
			t.Fatalf("offer %v: close %d %q", offer, code, reason)
		}
	}
}

func TestSubprotocolHeaderParsing(t *testing.T) {
	r, _ := http.NewRequest(http.MethodGet, "/", nil)
	r.Header.Add("Sec-WebSocket-Protocol", " chat ,\twebssh.v2, webssh.v1 ")
	if v := pickVersion(r); v != 1 {
		t.Fatalf("pickVersion = %d", v)
	}
	r.Header.Set("Sec-WebSocket-Protocol", "webssh.v01, webssh.v")
	if v := pickVersion(r); v != 0 {
		t.Fatalf("pickVersion = %d", v)
	}
}

// The connection limit gives the page a readable reason (baseline
// condition): Python refused the handshake and the browser saw only a
// transport error.
func TestConnectionLimitHasReadableReason(t *testing.T) {
	t.Run("per user", func(t *testing.T) {
		e := newEnv(t, Config{MaxConnsPerUser: 2, MaxConns: 10}, nil)
		e.open(1, "a")
		e.open(1, "b")
		code, reason := e.dialRefused(1, "c")
		if code != websocket.StatusTryAgainLater || !strings.HasPrefix(reason, "connection_limit_user: at most 2 ") {
			t.Fatalf("close %d %q", code, reason)
		}
		if len(reason) > 123 {
			t.Fatalf("reason has %d bytes", len(reason))
		}
		e.open(2, "d") // another user is not affected
	})
	t.Run("server", func(t *testing.T) {
		e := newEnv(t, Config{MaxConnsPerUser: 5, MaxConns: 2}, nil)
		e.open(1, "a")
		e.open(2, "b")
		code, reason := e.dialRefused(3, "c")
		if code != websocket.StatusTryAgainLater || !strings.HasPrefix(reason, "connection_limit_server: ") {
			t.Fatalf("close %d %q", code, reason)
		}
	})
	t.Run("slot is free again after close", func(t *testing.T) {
		e := newEnv(t, Config{MaxConnsPerUser: 1}, nil)
		c := e.open(1, "a")
		_ = c.ws.Close(websocket.StatusNormalClosure, "")
		waitFor(t, func() bool { return e.srv.Stats().Conns == 0 })
		e.open(1, "b")
	})
	t.Run("refusals are bounded", func(t *testing.T) {
		e := newEnv(t, Config{MaxConnsPerUser: 1, RejectSlots: 1}, nil)
		e.open(1, "a")
		e.srv.rejectSlots <- struct{}{} // the one slot is busy
		defer func() { <-e.srv.rejectSlots }()
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		_, resp, err := e.dial(ctx, e.ts.URL, e.sessions.token(1, "b"))
		if err == nil || resp == nil || resp.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("got %v %v, want 503", err, resp)
		}
		if resp.Header.Get("Retry-After") == "" {
			t.Fatal("no Retry-After")
		}
	})
}

func (e *testEnv) dialRefused(uid int64, sid string) (websocket.StatusCode, string) {
	e.t.Helper()
	ctx, cancel := context.WithTimeout(e.t.Context(), 10*time.Second)
	defer cancel()
	ws, _, err := e.dial(ctx, e.ts.URL, e.sessions.token(uid, sid))
	if err != nil {
		e.t.Fatal(err)
	}
	defer ws.CloseNow()
	c := &client{t: e.t, ctx: ctx, ws: ws}
	return c.closeStatus()
}

func TestOversizedMessageCloses(t *testing.T) {
	e := newEnv(t, Config{ReadLimit: 1024}, nil)
	c := e.open(1, "s1")
	_ = c.ws.Write(c.ctx, websocket.MessageText, []byte(strings.Repeat(" ", 4096)))
	if code, _ := c.closeStatus(); code != websocket.StatusMessageTooBig {
		t.Fatalf("close %d", code)
	}
}

func TestReadLimitFitsLargestPayload(t *testing.T) {
	e := newEnv(t, Config{ReadLimit: 1024}, func(s *Server) {
		s.Mount(protocol.Handle("test.big", protocol.Spec{MaxPayload: 64 << 10},
			func(_ context.Context, _ protocol.Peer, r echoReq) (echoReq, error) { return r, nil }))
	})
	c := e.open(1, "s1")
	c.ws.SetReadLimit(1 << 20)
	big := strings.Repeat("x", 60<<10)
	if r := c.request(`{"v":1,"t":"test.big","id":"b","p":{"text":"` + big + `"}}`); !r.OK {
		t.Fatalf("result %+v", r)
	}
}

func TestCompressionIsNotNegotiated(t *testing.T) {
	e := newEnv(t, Config{}, nil)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, e.ts.URL+"/ws", nil)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range map[string]string{
		"Origin": e.ts.URL, "Cookie": DefaultCookieName + "=" + e.sessions.token(1, "s1"),
		"Connection": "Upgrade", "Upgrade": "websocket", "Sec-WebSocket-Version": "13",
		"Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==", "Sec-WebSocket-Protocol": "webssh.v1",
		"Sec-WebSocket-Extensions": "permessage-deflate; client_max_window_bits",
	} {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if ext := resp.Header.Get("Sec-WebSocket-Extensions"); ext != "" {
		t.Fatalf("server negotiated %q", ext)
	}
}

func TestShutdownClosesWithMaintenance(t *testing.T) {
	e := newEnv(t, Config{}, nil)
	c := e.open(1, "s1")
	done := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		done <- e.srv.Shutdown(ctx)
	}()
	if code, _ := c.closeStatus(); code != protocol.CloseMaintenance {
		t.Fatalf("close %d", code)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if _, resp, err := e.dial(ctx, e.ts.URL, e.sessions.token(2, "s2")); err == nil || resp == nil || resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("after shutdown: %v %v", err, resp)
	}
}

func TestLegacySocketIOGone(t *testing.T) {
	e := newEnv(t, Config{}, nil)
	resp, err := http.Get(e.ts.URL + "/socket.io/?EIO=4&transport=polling")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusGone || !strings.Contains(string(body), `"code":"version_unsupported"`) {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
}

func TestRegistrationAfterServingPanics(t *testing.T) {
	e := newEnv(t, Config{}, nil)
	e.open(1, "s1")
	defer func() {
		if recover() == nil {
			t.Fatal("Mount after serving did not panic")
		}
	}()
	e.srv.Mount(protocol.Handle("test.late", protocol.Spec{}, func(context.Context, protocol.Peer, protocol.Empty) (*protocol.Empty, error) { return nil, nil }))
}

// waitFor polls cond for up to 5 s.
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
