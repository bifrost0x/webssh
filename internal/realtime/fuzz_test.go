package realtime

import (
	"context"
	"encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/coder/websocket"

	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/principal/principaltest"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
)

// FuzzOriginCheck: no input panics, and an accepted Origin is a bare
// http(s) origin whose host and port equal the request's own.
func FuzzOriginCheck(f *testing.F) {
	for _, s := range []string{
		"http://webssh.lab:5000", "https://webssh.lab", "http://[::1]:5000", "null", "file://",
		"http://a@webssh.lab", "http://webssh.lab:5000/", "HTTP://WEBSSH.LAB.:05000", "http://webssh.lab:65536",
		"http://%77ebssh.lab:5000", "http://webssh.lab:5000#", "http://webssh.lab:5000?", "http://[::1", "http://::1",
	} {
		f.Add(s, "webssh.lab:5000", false)
	}
	f.Fuzz(func(t *testing.T, originHeader, host string, ignoreScheme bool) {
		p := OriginPolicy{IgnoreScheme: ignoreScheme}
		if _, err := p.Compile(); err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(http.MethodGet, "/ws", nil)
		r.Host = host
		r.Header.Set("Origin", originHeader)
		if p.Check(r) != nil {
			return
		}
		got, err := parseOrigin(originHeader)
		if err != nil {
			t.Fatalf("accepted unparsable origin %q", originHeader)
		}
		own, err := normalise(got.scheme, host)
		if err != nil || own.host != got.host || own.port != got.port {
			t.Fatalf("accepted %q for host %q", originHeader, host)
		}
		if !ignoreScheme {
			if own, _ := normalise("http", host); own != got {
				t.Fatalf("accepted %q for plain-HTTP host %q", originHeader, host)
			}
		}
		if strings.ContainsAny(got.host, "@/?#\\ ") {
			t.Fatalf("host %q", got.host)
		}
	})
}

// recorder is an endpoint without a socket for the dispatcher fuzz test.
type recorder struct {
	ctx    context.Context
	mu     sync.Mutex
	texts  [][]byte
	closed websocket.StatusCode
}

func (r *recorder) ID() uint64                     { return 1 }
func (r *recorder) Principal() principal.Principal { return principaltest.User(1) }
func (r *recorder) Context() context.Context       { return r.ctx }
func (r *recorder) SendEvent(string, any) error    { return nil }
func (r *recorder) SendBinary([]byte) error        { return nil }
func (r *recorder) async(f func()) bool            { f(); return true }

func (r *recorder) sendText(b []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.texts = append(r.texts, b)
	return nil
}

func (r *recorder) closeWith(code websocket.StatusCode, _ string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = code
}

// FuzzDispatch: an arbitrary text frame never panics the dispatcher. It
// is either a protocol violation (no reply), or a valid envelope that gets
// exactly one well-formed result when it carries an id and none
// otherwise, and no reply ever leaks handler internals.
func FuzzDispatch(f *testing.F) {
	for _, s := range []string{
		`{"v":1,"t":"test.echo","id":"a","p":{"text":"x"}}`,
		`{"v":1,"t":"test.mutate","id":"b"}`,
		`{"v":1,"t":"test.fail","id":"c"}`,
		`{"v":1,"t":"test.panic","id":"d"}`,
		`{"v":1,"t":"session.keepalive"}`,
		`{"v":1,"t":"no.such","id":"e"}`,
		`{"v":1,"t":"test.echo","id":"f","p":{"text":"x","text":"y"}}`,
		`{"v":1,"t":"test.echo"}}`, `[]`, `null`, "\xff",
	} {
		f.Add([]byte(s))
	}
	sessions := newFakeSessions()
	srv, err := NewServer(Config{}, Deps{Origin: &OriginPolicy{}, Sessions: sessions, Revocations: &sessions.feed, Log: discardLog()})
	if err != nil {
		f.Fatal(err)
	}
	testRoutes(new(atomic.Int32), nil)(srv)
	f.Fuzz(func(t *testing.T, frame []byte) {
		rec := &recorder{ctx: t.Context()}
		env, envErr := protocol.DecodeEnvelope(frame)
		err := srv.dispatch(rec, frame)
		if (err != nil) != (envErr != nil) {
			t.Fatalf("dispatch error %v, envelope error %v", err, envErr)
		}
		if err != nil {
			if len(rec.texts) != 0 {
				t.Fatal("reply to a protocol violation")
			}
			return
		}
		want := 0
		if env.ID != "" {
			want = 1
		}
		if len(rec.texts) != want {
			t.Fatalf("%d replies for id %q", len(rec.texts), env.ID)
		}
		for _, b := range rec.texts {
			reply, err := protocol.DecodeEnvelope(b)
			if err != nil || reply.T != protocol.TypeResult || reply.ID != env.ID {
				t.Fatalf("bad reply %s: %v", b, err)
			}
			var res protocol.Result
			if err := json.Unmarshal(reply.P, &res); err != nil {
				t.Fatal(err)
			}
			if res.OK == (res.Err != nil) {
				t.Fatalf("result %s", b)
			}
			if strings.Contains(string(b), "secret") {
				t.Fatalf("leak in %s", b)
			}
		}
	})
}
