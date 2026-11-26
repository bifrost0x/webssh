package httpapi

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/bifrost0x/webssh/internal/config"
	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/principal"
)

// fakeSessions maps tokens to principals. A token not in the map is not a
// session; err, when set, is returned for every lookup.
type fakeSessions struct {
	mu     sync.Mutex
	tokens map[string]principal.Principal
	err    error
	calls  atomic.Int64
}

func (f *fakeSessions) Authenticate(_ context.Context, token string) (principal.Principal, error) {
	f.calls.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return principal.Principal{}, f.err
	}
	p, ok := f.tokens[token]
	if !ok {
		return principal.Principal{}, fault.New(fault.AuthenticationNeeded, "")
	}
	return p, nil
}

type fakeMAC struct{ key []byte }

func (m fakeMAC) MAC(p keyring.Purpose, msg []byte) []byte {
	h := hmac.New(sha256.New, append([]byte(string(p)+"\x00"), m.key...))
	h.Write(msg)
	return h.Sum(nil)
}

// Principals of the tests.
var (
	alice    = principal.Principal{UserID: 1, SessionID: "s-alice", Username: "alice"}
	aliceTwo = principal.Principal{UserID: 1, SessionID: "s-alice-2", Username: "alice"}
	root     = principal.Principal{UserID: 2, SessionID: "s-root", Username: "root", IsAdmin: true}
	repair   = principal.Principal{UserID: 3, SessionID: "s-repair", Username: "bob", Recovery: true}
)

func testConfig() config.Config {
	return config.Config{
		Cookies:  config.Cookies{SessionName: "session", RememberName: "remember_token"},
		Accounts: config.Accounts{AdminPanelEnabled: true},
		Stores:   config.Stores{MaxRecoveryJSONSize: 16 << 10, MaxWebAuthnJSONSize: 32 << 10},
	}
}

type edge struct {
	t        testing.TB
	h        *Handler
	sessions *fakeSessions
	logs     *syncBuffer
}

// syncBuffer is a log sink that server goroutines and the test share.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type edgeOption func(*Options)

func withConfig(fn func(*config.Config)) edgeOption {
	return func(o *Options) { fn(&o.Config) }
}

// newEdge builds a handler with the fake session store and a mux route
// for every catalog route the test registers through register.
func newEdge(t testing.TB, opts ...edgeOption) *edge {
	t.Helper()
	logs := &syncBuffer{}
	sessions := &fakeSessions{tokens: map[string]principal.Principal{
		"tok-alice": alice, "tok-alice-2": aliceTwo, "tok-root": root, "tok-repair": repair,
	}}
	o := Options{
		Config:   testConfig(),
		Sessions: sessions,
		MAC:      fakeMAC{key: []byte("test key")},
		Assets:   testAssets(t),
		Logger:   slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Readiness: Readiness{
			Stopping: func() bool { return false },
			Database: pingFunc(func(context.Context) error { return nil }),
			DataDir:  t.TempDir(),
		},
	}
	for _, opt := range opts {
		opt(&o)
	}
	h, err := New(o)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return &edge{t: t, h: h, sessions: sessions, logs: logs}
}

type pingFunc func(context.Context) error

func (f pingFunc) Ping(ctx context.Context) error { return f(ctx) }

// echo answers 200 with the principal's user ID, so a test sees that the
// handler ran and with whom.
func echo(w http.ResponseWriter, r *http.Request) {
	p, _ := principal.From(r.Context())
	body, _ := io.ReadAll(r.Body)
	w.Header().Set("X-User", strconv.FormatInt(p.UserID, 10))
	w.Header().Set("X-Body-Len", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

type req struct {
	method  string
	target  string
	body    string
	token   string // session cookie value
	binding string // binding cookie value
	headers map[string]string
	remote  string
}

func (e *edge) do(rq req) *httptest.ResponseRecorder {
	e.t.Helper()
	if rq.method == "" {
		rq.method = http.MethodGet
	}
	r := httptest.NewRequest(rq.method, "http://webssh.test"+rq.target, strings.NewReader(rq.body))
	if rq.body == "" {
		r.Body = http.NoBody
		r.ContentLength = 0
	}
	if rq.remote != "" {
		r.RemoteAddr = rq.remote
	}
	if rq.token != "" {
		r.AddCookie(&http.Cookie{Name: "session", Value: rq.token})
	}
	if rq.binding != "" {
		r.AddCookie(&http.Cookie{Name: "session_binding", Value: rq.binding})
	}
	for k, v := range rq.headers {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	return w
}

// csrf returns a binding and the token of that binding for a session.
func (e *edge) csrf(sessionID string) (binding, token string) {
	binding = newBinding()
	return binding, e.h.csrfToken(binding, sessionID)
}
