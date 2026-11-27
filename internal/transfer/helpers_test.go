package transfer_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/files"
	"github.com/bifrost0x/webssh/internal/files/filestest"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/principal/principaltest"
	"github.com/bifrost0x/webssh/internal/transfer"
)

// regSources is a fake of the source registry: backends by source id,
// each owned by one browser session, with hold counting.
type regSources struct {
	mu       sync.Mutex
	backends map[string]files.Backend
	owners   map[string]principal.Principal
	held     map[string]int
}

func newSources() *regSources {
	return &regSources{backends: map[string]files.Backend{}, owners: map[string]principal.Principal{}, held: map[string]int{}}
}

func (s *regSources) add(id string, owner principal.Principal, b files.Backend) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.backends[id], s.owners[id] = b, owner
}

func (s *regSources) drop(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.backends, id)
}

func (s *regSources) Resolve(_ context.Context, p principal.Principal, id string, need files.Capability) (files.Backend, func(), error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.backends[id]
	o := s.owners[id]
	if !ok || o.UserID != p.UserID || o.SessionID != p.SessionID || !b.Capabilities().Ops.Has(need) {
		return nil, nil, fault.New(fault.SourceUnavailable, "")
	}
	s.held[id]++
	var once sync.Once
	return b, func() {
		once.Do(func() {
			s.mu.Lock()
			s.held[id]--
			s.mu.Unlock()
		})
	}, nil
}

func (s *regSources) holds() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, h := range s.held {
		n += h
	}
	return n
}

// quotas is a fake quota policy: per-kind and per-user limits.
type quotas struct {
	mu    sync.Mutex
	limit map[string]int64
	used  map[string]int64
}

func newQuotas() *quotas {
	return &quotas{limit: map[string]int64{"transfer": 2, "background_job": 1, "temp_bytes": 1 << 40}, used: map[string]int64{}}
}

func (q *quotas) Reserve(_ context.Context, kind string, userID, amount int64) (func(), error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	key := fmt.Sprint(kind, userID)
	if q.used[key]+amount > q.limit[kind] {
		return nil, fault.New(fault.Busy, kind+" quota exceeded")
	}
	q.used[key] += amount
	var once sync.Once
	return func() {
		once.Do(func() {
			q.mu.Lock()
			q.used[key] -= amount
			q.mu.Unlock()
		})
	}, nil
}

func (q *quotas) inUse() int64 {
	q.mu.Lock()
	defer q.mu.Unlock()
	var n int64
	for _, v := range q.used {
		n += v
	}
	return n
}

// events records what the manager sends.
type events struct {
	mu       sync.Mutex
	progress []transfer.Progress
	finished []transfer.Finished
	ch       chan transfer.Finished
}

func newEvents() *events { return &events{ch: make(chan transfer.Finished, 64)} }

func (e *events) Progress(_ int64, ev transfer.Progress) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.progress = append(e.progress, ev)
}

func (e *events) Finished(_ int64, ev transfer.Finished) {
	e.mu.Lock()
	e.finished = append(e.finished, ev)
	e.mu.Unlock()
	e.ch <- ev
}

func (e *events) wait(t *testing.T, id string) transfer.Finished {
	t.Helper()
	timeout := time.After(10 * time.Second)
	for {
		select {
		case ev := <-e.ch:
			if ev.TransferID == id {
				return ev
			}
		case <-timeout:
			t.Fatalf("transfer %s did not finish", id)
		}
	}
}

// audit records audit events.
type auditLog struct {
	mu     sync.Mutex
	events [][]any
}

func (a *auditLog) Security(event string, kv ...any) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, append([]any{event}, kv...))
}

// env is a manager on fakes with one user who owns sources a and b.
type env struct {
	t     *testing.T
	m     *transfer.Manager
	src   *regSources
	quota *quotas
	ev    *events
	audit *auditLog
	owner principal.Principal
	a, b  *filestest.Backend
	mux   *http.ServeMux
}

func newEnv(t *testing.T, mutate ...func(*transfer.Options)) *env {
	t.Helper()
	e := &env{t: t, src: newSources(), quota: newQuotas(), ev: newEvents(), audit: &auditLog{}, owner: principaltest.User(7),
		a: filestest.New(), b: filestest.New()}
	e.src.add("sftp-session:a", e.owner, e.a)
	e.src.add("smb-quick:b", e.owner, e.b)
	o := transfer.Options{Sources: e.src, Quotas: e.quota, Events: e.ev, Audit: e.audit, BasePath: "/root"}
	for _, f := range mutate {
		f(&o)
	}
	e.m = transfer.New(o)
	e.mux = http.NewServeMux()
	e.mux.HandleFunc(transfer.RouteDownload, e.m.DownloadHTTP)
	e.mux.HandleFunc(transfer.RouteFolderDownload, e.m.FolderHTTP)
	e.mux.HandleFunc(transfer.RouteUpload, e.m.UploadHTTP)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := e.m.Shutdown(ctx); err != nil {
			t.Errorf("shutdown: %v", err)
		}
	})
	return e
}

func (e *env) caller() files.Caller { return files.Caller{P: e.owner, Peer: 1} }

func (e *env) prepare(rq transfer.PrepareRequest) transfer.Prepared {
	e.t.Helper()
	pr, err := e.m.Prepare(e.t.Context(), e.caller(), rq)
	if err != nil {
		e.t.Fatalf("prepare %+v: %v", rq, err)
	}
	return pr
}

// response is the answer of one request; aborted when the handler cut
// the connection (http.ErrAbortHandler).
type response struct {
	*httptest.ResponseRecorder
	aborted bool
}

// do runs one HTTP request as p through the transfer routes.
func (e *env) do(p principal.Principal, method, url string, body io.Reader, size int64) response {
	e.t.Helper()
	return e.doCtx(e.t.Context(), p, method, url, body, size)
}

func (e *env) doCtx(ctx context.Context, p principal.Principal, method, url string, body io.Reader, size int64) (out response) {
	req := httptest.NewRequestWithContext(principal.With(ctx, p), method, strings.TrimPrefix(url, "/root"), body)
	req.ContentLength = size
	out.ResponseRecorder = httptest.NewRecorder()
	defer func() {
		if v := recover(); v != nil {
			if v != http.ErrAbortHandler {
				panic(v)
			}
			out.aborted = true
		}
	}()
	e.mux.ServeHTTP(out.ResponseRecorder, req)
	return out
}

func (e *env) idle() {
	e.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for e.src.holds() != 0 || e.quota.inUse() != 0 {
		if time.Now().After(deadline) {
			e.t.Fatalf("still held: %d sources, %d quota", e.src.holds(), e.quota.inUse())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func body(b []byte) io.Reader { return bytes.NewReader(b) }
