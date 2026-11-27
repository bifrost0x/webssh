package httpapi

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/config"
	"github.com/bifrost0x/webssh/internal/principal"
)

func TestBodyBudget(t *testing.T) {
	b := newBodyBudget(10)
	if !b.acquire(t.Context(), 6, time.Millisecond) || !b.acquire(t.Context(), 4, time.Millisecond) {
		t.Fatal("the budget refused bytes it has")
	}
	if b.acquire(t.Context(), 1, 10*time.Millisecond) {
		t.Fatal("the budget gave more than it has")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if b.acquire(ctx, 1, time.Minute) {
		t.Fatal("acquire ignored the cancelled context")
	}
	got := make(chan bool)
	go func() { got <- b.acquire(t.Context(), 5, time.Minute) }()
	time.Sleep(10 * time.Millisecond)
	b.release(6)
	if !<-got {
		t.Fatal("a waiter was not served after a release")
	}
	if b.acquire(t.Context(), 2, time.Millisecond) {
		t.Fatal("released 6, took 5: only 1 byte is free")
	}
	if !b.acquire(t.Context(), 0, 0) {
		t.Fatal("an empty body needs no budget")
	}
}

// RS8-01: a refused request makes the edge read nothing of its body: no
// session, a session without the access level, a foreign origin.
func TestRefusedRequestReadsNoBody(t *testing.T) {
	e := newEdge(t)
	e.h.Mux().HandleFunc("PUT /api/profiles/{id}/context", echo)
	e.h.Mux().HandleFunc("POST /admin/api/users/{user_id}/{action}", echo)
	binding, token := e.csrf(alice.SessionID)
	cases := []struct {
		name, method, path, cookie string
		headers                    map[string]string
		want                       int
	}{
		{"no session", http.MethodPut, "/api/profiles/7/context", "", nil, http.StatusUnauthorized},
		{"unknown session", http.MethodPut, "/api/profiles/7/context", "tok-nobody", nil, http.StatusUnauthorized},
		{"not an administrator", http.MethodPost, "/admin/api/users/2/lock", "tok-alice", nil, http.StatusForbidden},
		{"recovery session", http.MethodPut, "/api/profiles/7/context", "tok-repair", nil, http.StatusForbidden},
		{"foreign origin", http.MethodPut, "/api/profiles/7/context", "tok-alice", map[string]string{"Origin": "https://evil.test", "X-CSRFToken": token}, http.StatusForbidden},
	}
	for _, c := range cases {
		body := &countingBody{size: hostContextRequestLimit}
		r := httptest.NewRequest(c.method, "http://webssh.test"+c.path, nil)
		r.Body, r.ContentLength = body, int64(body.size)
		r.Header.Set("Accept", "application/json")
		if c.cookie != "" {
			r.AddCookie(&http.Cookie{Name: "session", Value: c.cookie})
			r.AddCookie(&http.Cookie{Name: "session_binding", Value: binding})
		}
		for k, v := range c.headers {
			r.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		e.h.ServeHTTP(w, r)
		if w.Code != c.want || body.n != 0 {
			t.Errorf("%s: %d, read %d bytes; want %d and nothing read", c.name, w.Code, body.n, c.want)
		}
	}
}

// Routes without a session take at most publicRequestLimit, below their
// own route limit.
func TestPublicRoutesHaveASmallLimit(t *testing.T) {
	e := newEdge(t, withConfig(func(c *config.Config) { c.Stores.MaxRecoveryJSONSize = 4096 }))
	e.h.Mux().HandleFunc("POST /login", echo)
	e.h.Mux().HandleFunc("POST /api/webauthn/auth/verify", echo)
	binding, token := e.csrf("")
	for _, path := range []string{"/login", "/api/webauthn/auth/verify"} {
		for size, want := range map[int]int{publicRequestLimit: 200, publicRequestLimit + 1: 413} {
			w := e.do(req{method: http.MethodPost, target: path, body: strings.Repeat("a", size), binding: binding,
				headers: map[string]string{"X-CSRFToken": token}})
			if w.Code != want {
				t.Errorf("%s with %d bytes: %d, want %d", path, size, w.Code, want)
			}
		}
	}
	if got := e.h.bodyLimit("/api/auth/recovery", AccessPublic); got != 4096 {
		t.Errorf("the recovery route keeps its smaller limit: %d", got)
	}
}

// When the budget stays exhausted the request is answered 503 without
// reading its body.
func TestExhaustedBudgetAnswersBusy(t *testing.T) {
	e := newEdge(t)
	e.h.Mux().HandleFunc("POST /api/account/preferences", echo)
	e.h.signedIn = newBodyBudget(100)
	e.h.budgetWait = 10 * time.Millisecond
	binding, token := e.csrf(alice.SessionID)
	do := func(size int) *httptest.ResponseRecorder {
		return e.do(req{method: http.MethodPost, target: "/api/account/preferences", body: strings.Repeat("a", size), token: "tok-alice",
			binding: binding, headers: map[string]string{"X-CSRFToken": token, "Accept": "application/json"}})
	}
	if w := do(100); w.Code != http.StatusOK {
		t.Fatalf("within the budget: %d", w.Code)
	}
	if w := do(101); w.Code != http.StatusServiceUnavailable || w.Header().Get("Retry-After") != "1" {
		t.Fatalf("over the budget: %d, Retry-After %q", w.Code, w.Header().Get("Retry-After"))
	}
	if w := do(100); w.Code != http.StatusOK {
		t.Fatalf("the budget was not returned after the request: %d", w.Code)
	}
}

// FB8-2: one account holds at most its share of the signed-in budget,
// across all of its sessions; another account still gets the rest. The
// share is returned when the request ends.
func TestUserShareOfTheBodyBudget(t *testing.T) {
	e := newEdge(t)
	entered, leave := make(chan struct{}), make(chan struct{})
	e.h.Mux().HandleFunc("PUT /api/profiles/{id}/context", func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		<-leave
		echo(w, r)
	})
	e.h.Mux().HandleFunc("POST /api/account/preferences", echo)
	e.h.signedIn = newBodyBudget(1000)
	e.h.users = newUserBudgets(100)
	e.h.budgetWait = 20 * time.Millisecond
	post := func(p principal.Principal, cookie string, size int) *httptest.ResponseRecorder {
		binding, token := e.csrf(p.SessionID)
		return e.do(req{method: http.MethodPost, target: "/api/account/preferences", body: strings.Repeat("a", size), token: cookie,
			binding: binding, headers: map[string]string{"X-CSRFToken": token, "Accept": "application/json"}})
	}
	binding, token := e.csrf(alice.SessionID)
	held := make(chan int)
	go func() {
		held <- e.do(req{method: http.MethodPut, target: "/api/profiles/7/context", body: strings.Repeat("a", 80), token: "tok-alice",
			binding: binding, headers: map[string]string{"X-CSRFToken": token, "Accept": "application/json"}}).Code
	}()
	<-entered
	if w := post(aliceTwo, "tok-alice-2", 21); w.Code != http.StatusServiceUnavailable || w.Header().Get("Retry-After") != "1" {
		t.Fatalf("a second session of the same account went over its share: %d", w.Code)
	}
	if w := post(aliceTwo, "tok-alice-2", 20); w.Code != http.StatusOK {
		t.Fatalf("within the account's share: %d", w.Code)
	}
	if w := post(root, "tok-root", 100); w.Code != http.StatusOK {
		t.Fatalf("another account was refused while the first held its share: %d", w.Code)
	}
	close(leave)
	if code := <-held; code != http.StatusOK {
		t.Fatalf("held request: %d", code)
	}
	if w := post(alice, "tok-alice", 100); w.Code != http.StatusOK {
		t.Fatalf("the share was not returned after the request: %d", w.Code)
	}
	if n := len(e.h.users.users); n != 0 {
		t.Fatalf("%d account entries remain without a body in flight", n)
	}
}

func TestUserBudgets(t *testing.T) {
	u := newUserBudgets(10)
	if !u.acquire(t.Context(), 1, 25, time.Millisecond) {
		t.Fatal("a body larger than the share must take the whole share, not wait forever")
	}
	if u.acquire(t.Context(), 1, 1, 5*time.Millisecond) {
		t.Fatal("the share is taken")
	}
	if !u.acquire(t.Context(), 2, 10, time.Millisecond) {
		t.Fatal("another account has its own share")
	}
	u.release(1, 25)
	u.release(2, 10)
	if !u.acquire(t.Context(), 1, 10, time.Millisecond) {
		t.Fatal("the share was not returned")
	}
	u.release(1, 10)
	if len(u.users) != 0 {
		t.Fatalf("entries remain: %v", u.users)
	}
}

// A body with a declared length is read into a buffer of exactly that
// size, not into a doubling buffer.
func TestReadBodyAllocatesTheDeclaredLength(t *testing.T) {
	const size = 300 << 10
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(strings.Repeat("a", size)))
	b, ok, err := readBody(httptest.NewRecorder(), r, hostContextRequestLimit)
	if err != nil || !ok || len(b) != size || cap(b) != size {
		t.Fatalf("len %d cap %d ok %v err %v", len(b), cap(b), ok, err)
	}
	short := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("abc"))
	short.ContentLength = 10
	if _, ok, err := readBody(httptest.NewRecorder(), short, 64); err == nil || !ok {
		t.Fatalf("a body shorter than its Content-Length: ok %v err %v", ok, err)
	}
	chunked := httptest.NewRequest(http.MethodPost, "/", io.MultiReader(strings.NewReader(strings.Repeat("a", 65))))
	chunked.ContentLength = -1
	if _, ok, _ := readBody(httptest.NewRecorder(), chunked, 64); ok {
		t.Fatal("a chunked body over the limit was accepted")
	}
}

// RS8-01 under load: many connections without a session announce a body
// of the largest route limit and send all but its last byte. The edge
// answers each with 401 at once and holds no body; before the fix it
// buffered 1 MiB per connection until the read deadline.
func TestUnauthenticatedBodiesDoNotHoldMemory(t *testing.T) {
	if testing.Short() {
		t.Skip("opens many connections")
	}
	const conns = 300
	e := newEdge(t)
	e.h.Mux().HandleFunc("PUT /api/profiles/{id}/context", echo)
	srv := httptest.NewUnstartedServer(e.h)
	ConfigureServer(srv.Config)
	srv.Start()
	defer srv.Close()
	addr := srv.Listener.Addr().String()

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	chunk := []byte(strings.Repeat("a", 64<<10))
	var wg sync.WaitGroup
	statuses := make(chan string, conns)
	held := make(chan net.Conn, conns)
	for range conns {
		wg.Go(func() {
			c, err := net.Dial("tcp", addr)
			if err != nil {
				statuses <- err.Error()
				return
			}
			held <- c
			_ = c.SetDeadline(time.Now().Add(20 * time.Second))
			status := make(chan string, 1)
			go func() {
				line, err := bufio.NewReader(c).ReadString('\n')
				if err != nil {
					line = err.Error()
				}
				status <- strings.TrimSpace(line)
			}()
			fmt.Fprintf(c, "PUT /api/profiles/7/context HTTP/1.1\r\nHost: %s\r\nAccept: application/json\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n", addr, hostContextRequestLimit)
			for left := hostContextRequestLimit - 1; left > 0; left -= len(chunk) {
				if _, err := c.Write(chunk[:min(left, len(chunk))]); err != nil {
					break // the server answered and closed the connection
				}
			}
			line := <-status
			statuses <- line
		})
	}
	wg.Wait()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	close(statuses)
	close(held)
	for c := range held {
		_ = c.Close()
	}
	for s := range statuses {
		if s != "HTTP/1.1 401 Unauthorized" {
			t.Fatalf("a connection got %q", s)
		}
	}
	// TotalAlloc counts every allocation since the start; buffering would
	// add about conns MiB.
	if grown := after.TotalAlloc - before.TotalAlloc; grown > 64<<20 {
		t.Fatalf("%d connections allocated %d MiB", conns, grown>>20)
	}
}
