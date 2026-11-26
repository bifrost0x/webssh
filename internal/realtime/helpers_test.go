package realtime

import (
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/principal/principaltest"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
)

// fakeSessions is a session service: tokens map to principals, and a
// revocation is committed (revoked set) before it is published, as the
// contract requires of internal/session.
type fakeSessions struct {
	mu      sync.Mutex
	tokens  map[string]principal.Principal
	revoked map[string]bool
	checks  int
	// onCheck, when set, runs at the start of every Check.
	onCheck func(principal.Principal)
	feed    principaltest.Revocations
}

func newFakeSessions() *fakeSessions {
	return &fakeSessions{tokens: map[string]principal.Principal{}, revoked: map[string]bool{}}
}

// token registers a session of user uid and returns its cookie value.
func (f *fakeSessions) token(uid int64, sid string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	tok := "tok-" + sid
	f.tokens[tok] = principal.Principal{UserID: uid, SessionID: sid, Username: "user" + strconv.FormatInt(uid, 10)}
	return tok
}

func (f *fakeSessions) set(tok string, p principal.Principal) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tokens[tok] = p
}

func (f *fakeSessions) Authenticate(_ context.Context, token string) (principal.Principal, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p, ok := f.tokens[token]
	if !ok || f.revoked[p.SessionID] {
		return principal.Principal{}, fault.New(fault.AuthenticationNeeded, "")
	}
	return p, nil
}

func (f *fakeSessions) Check(_ context.Context, p principal.Principal) error {
	f.mu.Lock()
	hook := f.onCheck
	f.checks++
	f.mu.Unlock()
	if hook != nil {
		hook(p)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.revoked[p.SessionID] {
		return fault.New(fault.AuthenticationNeeded, "")
	}
	return nil
}

func (f *fakeSessions) checkCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.checks
}

// markRevoked commits a revocation without publishing it.
func (f *fakeSessions) markRevoked(sid string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revoked[sid] = true
}

// revoke commits and publishes, like Revoke of internal/session.
func (f *fakeSessions) revoke(uid int64, sid string, reason principal.Reason) {
	f.markRevoked(sid)
	f.feed.Revoke(principal.Revocation{SessionID: sid, UserID: uid, Reason: reason})
}

type fakeLimiter struct{ deny bool }

func (l *fakeLimiter) Allow(int64, string) (bool, time.Duration) {
	return !l.deny, 1500 * time.Millisecond
}

type auditCall struct {
	typ string
	err error
}

type fakeAuditor struct {
	mu    sync.Mutex
	calls []auditCall
}

func (a *fakeAuditor) RealtimeCall(_ context.Context, _ principal.Principal, typ string, err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls = append(a.calls, auditCall{typ, err})
}

func (a *fakeAuditor) all() []auditCall {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]auditCall(nil), a.calls...)
}

func discardLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// testEnv is one endpoint behind an httptest server.
type testEnv struct {
	t        *testing.T
	srv      *Server
	ts       *httptest.Server
	sessions *fakeSessions
	limiter  *fakeLimiter
	auditor  *fakeAuditor
}

// newEnv builds an endpoint; mount registers routes before it serves.
func newEnv(t *testing.T, cfg Config, mount func(*Server)) *testEnv {
	t.Helper()
	e := &testEnv{t: t, sessions: newFakeSessions(), limiter: &fakeLimiter{}, auditor: &fakeAuditor{}}
	srv, err := NewServer(cfg, Deps{
		Origin: &OriginPolicy{}, Sessions: e.sessions, Revocations: &e.sessions.feed,
		Limiter: e.limiter, Auditor: e.auditor, Log: discardLog(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if mount != nil {
		mount(srv)
	}
	e.srv = srv
	mux := http.NewServeMux()
	mux.Handle("/ws", srv)
	mux.Handle("/socket.io/", LegacySocketIO())
	e.ts = httptest.NewServer(mux)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		e.ts.Close()
	})
	return e
}

func (e *testEnv) wsURL() string { return "ws" + strings.TrimPrefix(e.ts.URL, "http") + "/ws" }

// dial opens a connection with the given origin ("" = none) and cookie
// ("" = none), offering webssh.v1 unless subprotocols are given.
func (e *testEnv) dial(ctx context.Context, origin, cookie string, subprotocols ...string) (*websocket.Conn, *http.Response, error) {
	h := http.Header{}
	if origin != "" {
		h.Set("Origin", origin)
	}
	if cookie != "" {
		h.Set("Cookie", DefaultCookieName+"="+cookie)
	}
	if subprotocols == nil {
		subprotocols = []string{protocol.Subprotocol(protocol.Version)}
	}
	return websocket.Dial(ctx, e.wsURL(), &websocket.DialOptions{HTTPHeader: h, Subprotocols: subprotocols})
}

// client is an open, authenticated connection after hello.
type client struct {
	t     *testing.T
	ctx   context.Context
	ws    *websocket.Conn
	hello protocol.Hello
}

// open dials with a valid session of uid/sid and reads hello.
func (e *testEnv) open(uid int64, sid string) *client {
	e.t.Helper()
	return e.openToken(e.sessions.token(uid, sid))
}

// tryOpen is open for other goroutines than the test's: it reports
// instead of failing.
func (e *testEnv) tryOpen(uid int64, sid string) (*client, error) {
	ctx, cancel := context.WithTimeout(e.t.Context(), 60*time.Second)
	e.t.Cleanup(cancel)
	ws, _, err := e.dial(ctx, e.ts.URL, e.sessions.token(uid, sid))
	if err != nil {
		return nil, err
	}
	e.t.Cleanup(func() { _ = ws.CloseNow() })
	typ, b, err := ws.Read(ctx)
	if err != nil {
		return nil, err
	}
	if env, err := protocol.DecodeEnvelope(b); typ != websocket.MessageText || err != nil || env.T != protocol.TypeHello {
		return nil, errors.New("first message is not hello")
	}
	return &client{t: e.t, ctx: ctx, ws: ws}, nil
}

func (e *testEnv) openToken(tok string) *client {
	e.t.Helper()
	ctx, cancel := context.WithTimeout(e.t.Context(), 20*time.Second)
	e.t.Cleanup(cancel)
	ws, _, err := e.dial(ctx, e.ts.URL, tok)
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { _ = ws.CloseNow() })
	c := &client{t: e.t, ctx: ctx, ws: ws}
	env := c.read()
	if env.T != protocol.TypeHello {
		e.t.Fatalf("first message %q, want hello", env.T)
	}
	if err := json.Unmarshal(env.P, &c.hello); err != nil {
		e.t.Fatal(err)
	}
	return c
}

func (c *client) write(msg string) {
	c.t.Helper()
	if err := c.ws.Write(c.ctx, websocket.MessageText, []byte(msg)); err != nil {
		c.t.Fatal(err)
	}
}

func (c *client) read() protocol.Envelope {
	c.t.Helper()
	typ, b, err := c.ws.Read(c.ctx)
	if err != nil {
		c.t.Fatalf("read: %v", err)
	}
	if typ != websocket.MessageText {
		c.t.Fatalf("got binary frame, want text")
	}
	env, err := protocol.DecodeEnvelope(b)
	if err != nil {
		c.t.Fatalf("server sent an invalid envelope %s: %v", b, err)
	}
	return env
}

// request sends msg and returns the result payload.
func (c *client) request(msg string) protocol.Result {
	c.t.Helper()
	c.write(msg)
	env := c.read()
	if env.T != protocol.TypeResult {
		c.t.Fatalf("got %q, want result", env.T)
	}
	var r protocol.Result
	if err := json.Unmarshal(env.P, &r); err != nil {
		c.t.Fatal(err)
	}
	return r
}

// closeStatus reads until the connection ends and returns the close
// status and reason.
func (c *client) closeStatus() (websocket.StatusCode, string) {
	c.t.Helper()
	for {
		_, _, err := c.ws.Read(c.ctx)
		if err == nil {
			continue
		}
		if ce, ok := errors.AsType[websocket.CloseError](err); ok {
			return ce.Code, ce.Reason
		}
		return -1, err.Error()
	}
}

func errCode(r protocol.Result) fault.Code {
	if r.Err == nil {
		return ""
	}
	return r.Err.Code
}
