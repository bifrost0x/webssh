package terminal_test

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/principal/principaltest"
	"github.com/bifrost0x/webssh/internal/realtime"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
	"github.com/bifrost0x/webssh/internal/ssh/client"
	"github.com/bifrost0x/webssh/internal/terminal"
)

// echoShell echoes every input back as output, like a shell with a PTY.
type echoShell struct {
	pr   *io.PipeReader
	pw   *io.PipeWriter
	once sync.Once
	gone chan struct{}
}

func newEchoShell() *echoShell {
	pr, pw := io.Pipe()
	return &echoShell{pr: pr, pw: pw, gone: make(chan struct{})}
}

func (s *echoShell) Read(p []byte) (int, error)  { return s.pr.Read(p) }
func (s *echoShell) Write(p []byte) (int, error) { return s.pw.Write(p) }
func (s *echoShell) Resize(int, int) error       { return nil }
func (s *echoShell) Wait() error                 { <-s.gone; return nil }
func (s *echoShell) Close() error {
	s.once.Do(func() { _ = s.pw.Close(); close(s.gone) })
	return nil
}

type echoShells struct {
	mu     sync.Mutex
	shells []*echoShell
}

func (e *echoShells) OpenShell(context.Context, client.Target, client.Interaction, int, int) (client.Shell, error) {
	s := newEchoShell()
	e.mu.Lock()
	e.shells = append(e.shells, s)
	e.mu.Unlock()
	return s, nil
}

// sessions validates "tok-<sid>" cookies; revoked sessions fail.
type sessions struct {
	mu      sync.Mutex
	revoked map[string]bool
	feed    principaltest.Revocations
}

func (s *sessions) Authenticate(_ context.Context, token string) (principal.Principal, error) {
	var uid int64
	var sid string
	if _, err := fmt.Sscanf(token, "tok-%d-%s", &uid, &sid); err != nil {
		return principal.Principal{}, fault.New(fault.AuthenticationNeeded, "")
	}
	return principal.Principal{UserID: uid, SessionID: sid, Username: fmt.Sprint("u", uid)}, s.Check(context.Background(), principal.Principal{SessionID: sid})
}

func (s *sessions) Check(_ context.Context, p principal.Principal) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.revoked[p.SessionID] {
		return fault.New(fault.AuthenticationNeeded, "")
	}
	return nil
}

func (s *sessions) revoke(uid int64, sid string, reason principal.Reason) {
	s.mu.Lock()
	s.revoked[sid] = true
	s.mu.Unlock()
	s.feed.Revoke(principal.Revocation{SessionID: sid, UserID: uid, Reason: reason})
}

type rig struct {
	t      *testing.T
	ts     *httptest.Server
	m      *terminal.Manager
	shells *echoShells
	sess   *sessions
}

func newRig(t *testing.T, cfg terminal.Config) *rig {
	t.Helper()
	r := &rig{t: t, shells: &echoShells{}, sess: &sessions{revoked: map[string]bool{}}}
	log := slog.New(slog.DiscardHandler)
	m, err := terminal.New(cfg, terminal.Deps{Shells: r.shells, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := realtime.NewServer(realtime.Config{MaxConnsPerUser: 64, MaxConns: 256},
		realtime.Deps{Origin: &realtime.OriginPolicy{}, Sessions: r.sess, Revocations: &r.sess.feed, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	srv.Mount(m.Routes()...)
	srv.HandleBinary(m.HandleBinary)
	srv.SetRestorer(m)
	srv.OnKeepalive(m.Keepalive)
	srv.OnClose(m.PeerClosed)
	unsubscribe := r.sess.feed.Subscribe(m.Revoked)
	r.m = m
	r.ts = httptest.NewServer(srv)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			t.Errorf("realtime shutdown: %v", err)
		}
		r.ts.Close()
		if err := m.Shutdown(ctx); err != nil {
			t.Errorf("terminal shutdown: %v", err)
		}
		unsubscribe()
	})
	return r
}

// message is one received WebSocket message.
type message struct {
	env   protocol.Envelope
	frame []byte
}

// conn is a browser connection that collects everything it receives.
type conn struct {
	t     *testing.T
	ws    *websocket.Conn
	in    chan message
	hello protocol.Hello
	ids   int
	done  chan struct{}
	code  websocket.StatusCode
}

func (r *rig) dial(uid int64, sid string) *conn {
	r.t.Helper()
	ctx, cancel := context.WithTimeout(r.t.Context(), 30*time.Second)
	r.t.Cleanup(cancel)
	h := http.Header{"Origin": {r.ts.URL}, "Cookie": {fmt.Sprintf("session=tok-%d-%s", uid, sid)}}
	ws, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(r.ts.URL, "http"), &websocket.DialOptions{
		HTTPHeader: h, Subprotocols: []string{protocol.Subprotocol(protocol.Version)}})
	if err != nil {
		r.t.Fatal(err)
	}
	ws.SetReadLimit(1 << 20)
	c := &conn{t: r.t, ws: ws, in: make(chan message, 4096), done: make(chan struct{})}
	r.t.Cleanup(func() { _ = ws.CloseNow() })
	go func() {
		defer close(c.done)
		for {
			typ, b, err := ws.Read(context.Background())
			if err != nil {
				c.code = websocket.CloseStatus(err)
				return
			}
			if typ == websocket.MessageBinary {
				c.in <- message{frame: b}
				continue
			}
			env, err := protocol.DecodeEnvelope(b)
			if err != nil {
				r.t.Errorf("invalid envelope: %v", err)
				return
			}
			c.in <- message{env: env}
		}
	}()
	m := c.next()
	if m.env.T != protocol.TypeHello || json.Unmarshal(m.env.P, &c.hello) != nil {
		r.t.Fatalf("first message %+v", m.env)
	}
	return c
}

func (c *conn) recv() (message, bool) {
	select {
	case m := <-c.in:
		return m, true
	case <-time.After(5 * time.Second):
		return message{}, false
	}
}

func (c *conn) next() message {
	c.t.Helper()
	m, ok := c.recv()
	if !ok {
		c.t.Fatal("no message")
	}
	return m
}

// result waits for the result of id without failing the test, for use
// from other goroutines.
func (c *conn) result(id string) (protocol.Result, bool) {
	for {
		m, ok := c.recv()
		if !ok {
			return protocol.Result{}, false
		}
		if m.env.T == protocol.TypeResult && m.env.ID == id {
			var res protocol.Result
			return res, json.Unmarshal(m.env.P, &res) == nil
		}
	}
}

// send writes a request and returns its id; a failed write shows as a
// missing result.
func (c *conn) send(typ string, payload any) string {
	c.ids++
	id := fmt.Sprint("q", c.ids)
	b, err := protocol.EncodeEnvelope(typ, id, payload)
	if err == nil {
		err = c.ws.Write(context.Background(), websocket.MessageText, b)
	}
	if err != nil {
		c.t.Errorf("send %s: %v", typ, err)
	}
	return id
}

func (c *conn) binary(b []byte) {
	if err := c.ws.Write(context.Background(), websocket.MessageBinary, b); err != nil {
		c.t.Errorf("binary write: %v", err)
	}
}

// until collects messages until the result of id and returns them with it.
func (c *conn) until(id string) ([]message, protocol.Result) {
	c.t.Helper()
	var got []message
	for {
		m := c.next()
		if m.env.T == protocol.TypeResult && m.env.ID == id {
			var res protocol.Result
			if err := json.Unmarshal(m.env.P, &res); err != nil {
				c.t.Fatal(err)
			}
			return got, res
		}
		got = append(got, m)
	}
}

// output reads output frames of ch, acknowledging each, until want has
// arrived.
func (c *conn) output(ch uint32, want string) {
	c.t.Helper()
	var b bytes.Buffer
	for !strings.Contains(b.String(), want) {
		m := c.next()
		if m.frame == nil {
			continue
		}
		f, err := protocol.DecodeFrame(m.frame, 1<<20)
		if err != nil || f.Kind != protocol.KindOutput || f.Channel != ch {
			c.t.Fatalf("frame %v %+v", err, f)
		}
		b.Write(f.Data)
		c.binary(protocol.AppendFrame(nil, protocol.Frame{Kind: protocol.KindAck, Channel: ch, Seq: f.Seq}))
	}
}

func openTarget() protocol.OpenTarget {
	return protocol.OpenTarget{Host: "h.example", Username: "u", AuthType: "password", Password: "pw"}
}

func (c *conn) open(ch uint32) protocol.TerminalOpened {
	c.t.Helper()
	id := c.send(protocol.TypeTerminalOpen, protocol.TerminalOpen{Ch: ch, RequestID: fmt.Sprint("r", ch), Target: openTarget()})
	_, res := c.until(id)
	var out protocol.TerminalOpened
	if !res.OK || json.Unmarshal(res.P, &out) != nil {
		c.t.Fatalf("open: %+v", res.Err)
	}
	return out
}

func (c *conn) input(ch uint32, seq uint64, s string) {
	c.binary(protocol.AppendFrame(nil, protocol.Frame{Kind: protocol.KindInput, Channel: ch, Seq: seq, Data: []byte(s)}))
}

func TestWebSocketTerminal(t *testing.T) {
	r := newRig(t, terminal.Config{})
	a := r.dial(1, "s1")
	opened := a.open(1)
	a.input(1, 1, "hello\r")
	a.output(1, "hello\r")

	// A reload: the new connection lists the session and re-attaches; the
	// replay arrives before the result and ends at its watermark.
	b := r.dial(1, "s2")
	if len(b.hello.Restorable) != 1 || b.hello.Restorable[0].SessionID != opened.SessionID || b.hello.Restorable[0].LastSeq == 0 {
		t.Fatalf("restorable %+v", b.hello.Restorable)
	}
	id := b.send(protocol.TypeTerminalAttach, protocol.TerminalAttach{Ch: 3, SessionID: opened.SessionID})
	before, res := b.until(id)
	var att protocol.TerminalAttached
	if !res.OK || json.Unmarshal(res.P, &att) != nil || !att.Full {
		t.Fatalf("attach %+v", res)
	}
	var replay bytes.Buffer
	for _, m := range before {
		f, _ := protocol.DecodeFrame(m.frame, 1<<20)
		if f.Flags&protocol.FlagReplay == 0 || f.Seq > att.Seq {
			t.Fatalf("frame before the result: %+v", f)
		}
		replay.Write(f.Data)
	}
	if replay.String() != "hello\r" {
		t.Fatalf("replay %q", replay.String())
	}
	// Both connections see new output.
	a.input(1, 2, "again")
	a.output(1, "again")
	b.output(3, "again")

	// Signing out in b revokes its session: b closes with 4003 at once, and
	// the user's SSH sessions end, which a learns from terminal.closed.
	r.sess.revoke(1, "s2", principal.ReasonLogout)
	select {
	case <-b.done:
	case <-time.After(time.Second):
		t.Fatal("revoked connection still open after 1 s")
	}
	if b.code != protocol.CloseUnauthenticated {
		t.Fatalf("close code %d", b.code)
	}
	for {
		m := a.next()
		if m.env.T == protocol.TypeTerminalClosed {
			break
		}
	}
	if st := r.m.Stats(); st.Sessions != 0 || st.Reserved != 0 {
		t.Fatalf("after sign-out %+v", st)
	}
	r.shells.mu.Lock()
	defer r.shells.mu.Unlock()
	select {
	case <-r.shells.shells[0].gone:
	case <-time.After(time.Second):
		t.Fatal("SSH shell still open after the revocation")
	}
}

// One hundred sessions on ten connections echo in parallel; afterwards no
// goroutine is left (DoD: load test without leak).
func TestWebSocketHundredSessions(t *testing.T) {
	base := runtime.NumGoroutine()
	// Registered first, so it runs after the rig's cleanup.
	t.Cleanup(func() {
		deadline := time.Now().Add(5 * time.Second)
		for runtime.NumGoroutine() > base+2 && time.Now().Before(deadline) {
			time.Sleep(20 * time.Millisecond)
		}
		if n := runtime.NumGoroutine(); n > base+2 {
			buf := make([]byte, 1<<20)
			t.Errorf("%d goroutines after shutdown, %d before:\n%s", n, base, buf[:runtime.Stack(buf, true)])
		}
	})
	r := newRig(t, terminal.Config{SessionsGlobal: 200, SessionsPerUser: 150})
	conns := make([]*conn, 10)
	for i := range conns {
		conns[i] = r.dial(1, fmt.Sprint("s", i))
	}
	errs := make(chan string, len(conns))
	var wg sync.WaitGroup
	for _, c := range conns {
		wg.Go(func() { errs <- echoTen(c) })
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		if e != "" {
			t.Fatal(e)
		}
	}
	if st := r.m.Stats(); st.Sessions != 100 {
		t.Fatalf("stats %+v", st)
	}
}

// echoTen opens ten sessions on c and waits for an echo on each. It
// returns a failure instead of failing the test (another goroutine).
func echoTen(c *conn) string {
	for ch := uint32(1); ch <= 10; ch++ {
		id := c.send(protocol.TypeTerminalOpen, protocol.TerminalOpen{Ch: ch, RequestID: fmt.Sprint("r", ch), Target: openTarget()})
		if res, ok := c.result(id); !ok || !res.OK {
			return fmt.Sprint("open: ", res.Err)
		}
	}
	for ch := uint32(1); ch <= 10; ch++ {
		c.input(ch, 1, fmt.Sprintf("ping-%d\r", ch))
	}
	got := map[uint32]string{}
	done := map[uint32]bool{}
	for len(done) < 10 {
		m, ok := c.recv()
		if !ok {
			return fmt.Sprintf("echo missing, have %v", got)
		}
		if m.frame == nil {
			continue
		}
		f, err := protocol.DecodeFrame(m.frame, 1<<20)
		if err != nil {
			return err.Error()
		}
		got[f.Channel] += string(f.Data)
		c.binary(protocol.AppendFrame(nil, protocol.Frame{Kind: protocol.KindAck, Channel: f.Channel, Seq: f.Seq}))
		if strings.Contains(got[f.Channel], fmt.Sprintf("ping-%d\r", f.Channel)) {
			done[f.Channel] = true
		}
	}
	return ""
}
