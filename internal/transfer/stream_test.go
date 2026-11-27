package transfer_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/files"
	"github.com/bifrost0x/webssh/internal/files/filestest"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/transfer"
)

// streamBackend serves generated files of any size and swallows writes,
// so nothing of a transfer is held in memory by the test itself. With
// gate set every chunk waits for a token from it, or for the end of the
// operation's context.
type streamBackend struct {
	*filestest.Backend
	size    int64
	gate    chan struct{}
	written atomic.Int64
	pending atomic.Int64 // writes begun and not ended (a staging file)
	served  atomic.Int64
}

func newStream(size int64) *streamBackend {
	return &streamBackend{Backend: filestest.New(), size: size}
}

type genReader struct {
	b   *streamBackend
	ctx context.Context
	n   int64
}

func (g *genReader) Read(p []byte) (int, error) {
	if g.n >= g.b.size {
		return 0, io.EOF
	}
	if g.b.gate != nil {
		select {
		case <-g.b.gate:
		case <-g.ctx.Done():
			return 0, fault.Wrap(fault.FileCancelled, g.ctx.Err(), "")
		}
	}
	k := int(min(int64(len(p)), g.b.size-g.n))
	for i := range k {
		p[i] = byte(g.n + int64(i))
	}
	g.n += int64(k)
	g.b.served.Add(int64(k))
	return k, nil
}

type genFile struct {
	*genReader
	e files.Entry
}

func (genFile) Close() error         { return nil }
func (f genFile) Entry() files.Entry { return f.e }

func (b *streamBackend) Stat(ctx context.Context, p string, follow bool) (files.Entry, error) {
	if p == "/gen" {
		return files.Entry{Name: "gen", Path: p, Size: b.size, Mode: 0o100644}, nil
	}
	return b.Backend.Stat(ctx, p, follow)
}

func (b *streamBackend) Open(ctx context.Context, p string, r files.Range) (files.Reader, error) {
	if p != "/gen" {
		return b.Backend.Open(ctx, p, r)
	}
	return genFile{&genReader{b: b, ctx: ctx}, files.Entry{Name: "gen", Path: p, Size: b.size, Mode: 0o100644}}, nil
}

// Write reads src in chunks and drops them; fewer or more bytes than
// declared fail like the real backends.
func (b *streamBackend) Write(ctx context.Context, p string, src io.Reader, o files.WriteOptions) (files.WriteResult, error) {
	b.pending.Add(1)
	defer b.pending.Add(-1)
	buf := make([]byte, 32<<10)
	var n int64
	for {
		if err := ctx.Err(); err != nil {
			return files.WriteResult{}, fault.Wrap(fault.FileCancelled, err, "")
		}
		k, err := src.Read(buf)
		n += int64(k)
		b.written.Add(int64(k))
		if o.Size >= 0 && n > o.Size {
			return files.WriteResult{}, fault.New(fault.SourceChanged, "")
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return files.WriteResult{}, fault.Wrap(fault.SourceChanged, err, "")
		}
	}
	if o.Size >= 0 && n != o.Size {
		return files.WriteResult{}, fault.New(fault.SourceChanged, "")
	}
	return files.WriteResult{Size: n}, nil
}

func streamEnv(t *testing.T, size int64, gated bool, mutate ...func(*transfer.Options)) (*env, *streamBackend) {
	e := newEnv(t, mutate...)
	s := newStream(size)
	if gated {
		s.gate = make(chan struct{})
	}
	e.src.add("sftp-quick:s", e.owner, s)
	return e, s
}

func TestCancelStopsARunningDownload(t *testing.T) {
	t.Parallel()
	e, s := streamEnv(t, 10<<20, true)
	pr := e.prepare(transfer.PrepareRequest{SourceID: "sftp-quick:s", Direction: transfer.Download, Path: "/gen"})
	done := make(chan response, 1)
	go func() { done <- e.do(e.owner, http.MethodGet, pr.URL, nil, 0) }()
	s.gate <- struct{}{}
	s.gate <- struct{}{}
	if st := e.m.CancelFor(e.owner.UserID, pr.TransferID); st != transfer.Cancelling {
		t.Fatalf("cancel %s", st)
	}
	if st := e.m.CancelFor(e.owner.UserID, pr.TransferID); st != transfer.Cancelling {
		t.Fatalf("second cancel %s", st)
	}
	r := <-done
	if !r.aborted {
		t.Fatal("a cancelled download ends without aborting the connection")
	}
	ev := e.ev.wait(t, pr.TransferID)
	if ev.State != transfer.Cancelled || ev.Failure == nil || ev.Failure.Code != fault.FileCancelled {
		t.Fatalf("finished %+v", ev)
	}
	e.idle()
	if st := e.m.CancelFor(e.owner.UserID, pr.TransferID); st != transfer.Cancelled {
		t.Fatalf("state after the end %s", st)
	}
	if st := e.m.CancelFor(8, pr.TransferID); st != transfer.CancelUnavailable {
		t.Fatalf("another user learns %s", st)
	}
}

func TestRevocationCancelsARunningUpload(t *testing.T) {
	t.Parallel()
	e, s := streamEnv(t, 0, false)
	pr := e.prepare(transfer.PrepareRequest{SourceID: "sftp-quick:s", Direction: transfer.Upload, Path: "/target"})
	body, w := io.Pipe()
	done := make(chan response, 1)
	go func() { done <- e.do(e.owner, http.MethodPost, pr.URL, body, 1<<20) }()
	_, _ = w.Write(make([]byte, 1000))
	e.m.Revoke(principal.Revocation{UserID: e.owner.UserID, SessionID: e.owner.SessionID})
	go func() { _, _ = w.Write(make([]byte, 1000)) }()
	r := <-done
	_ = w.Close()
	if got := failureBody(t, r); got["error_code"] != "SOURCE_UNAVAILABLE" {
		t.Fatalf("%d %v", r.Code, got)
	}
	if s.pending.Load() != 0 {
		t.Fatal("the write did not end")
	}
	e.idle()
}

func TestBrowserAbortCancelsAnUpload(t *testing.T) {
	t.Parallel()
	e, _ := streamEnv(t, 0, false)
	pr := e.prepare(transfer.PrepareRequest{SourceID: "sftp-quick:s", Direction: transfer.Upload, Path: "/target"})
	body, w := io.Pipe()
	done := make(chan response, 1)
	go func() { done <- e.do(e.owner, http.MethodPost, pr.URL, body, 1<<20) }()
	_, _ = w.Write(make([]byte, 1000))
	_ = w.CloseWithError(errors.New("client went away"))
	r := <-done
	if got := failureBody(t, r); got["error_code"] != "CANCELLED" {
		t.Fatalf("%d %v", r.Code, got)
	}
	if ev := e.ev.wait(t, pr.TransferID); ev.State != transfer.Cancelled {
		t.Fatalf("finished %+v", ev)
	}
	e.idle()
}

func TestClosedConnectionKeepsRunningHTTPTransfers(t *testing.T) {
	t.Parallel()
	e, s := streamEnv(t, 1<<20, true)
	e.a.PutFile("/f", []byte("x"))
	e.m.PeerOpened(e.owner.UserID, 1)
	e.m.PeerOpened(e.owner.UserID, 2)
	running := e.prepare(transfer.PrepareRequest{SourceID: "sftp-quick:s", Direction: transfer.Download, Path: "/gen"})
	pending, err := e.m.Prepare(t.Context(), e.caller(), transfer.PrepareRequest{SourceID: "sftp-session:a", Direction: transfer.Download, Path: "/f"})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan response, 1)
	go func() { done <- e.do(e.owner, http.MethodGet, running.URL, nil, 0) }()
	s.gate <- struct{}{}
	// Connection 1 prepared both; closing it ends the pending one only.
	e.m.PeerClosed(e.owner.UserID, 1)
	if ev := e.ev.wait(t, pending.TransferID); ev.State != transfer.Cancelled {
		t.Fatalf("pending after close %+v", ev)
	}
	e.m.PeerClosed(e.owner.UserID, 2)
	close(s.gate)
	if r := <-done; r.Code != 200 || r.aborted || int64(r.Body.Len()) != 1<<20 {
		t.Fatalf("running download after reconnect: %d aborted=%v %d", r.Code, r.aborted, r.Body.Len())
	}
	e.idle()
}

func TestLastConnectionCancelsPendingOfOtherConnections(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.a.PutFile("/f", []byte("x"))
	e.m.PeerOpened(e.owner.UserID, 5)
	pr := e.prepare(transfer.PrepareRequest{SourceID: "sftp-session:a", Direction: transfer.Download, Path: "/f"})
	e.m.PeerClosed(e.owner.UserID, 5) // the last one; the transfer was prepared on peer 1
	if ev := e.ev.wait(t, pr.TransferID); ev.State != transfer.Cancelled {
		t.Fatalf("%+v", ev)
	}
	e.idle()
}

func TestAdminListAndCancel(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.a.PutFile("/f", []byte("x"))
	pr := e.prepare(transfer.PrepareRequest{SourceID: "sftp-session:a", Direction: transfer.Download, Path: "/f"})
	items, total := e.m.Active(10)
	if total != 1 || len(items) != 1 || items[0].ID != pr.TransferID || items[0].UserID != 7 || items[0].State != transfer.Pending {
		t.Fatalf("active %+v %d", items, total)
	}
	if items, total := e.m.Active(0); len(items) != 0 || total != 1 {
		t.Fatalf("limit 0: %v %d", items, total)
	}
	if st, _ := e.m.Cancel(t.Context(), pr.TransferID); st != transfer.Cancelled {
		t.Fatalf("admin cancel %s", st)
	}
	if st, _ := e.m.Cancel(t.Context(), "nope"); st != transfer.CancelUnavailable {
		t.Fatalf("unknown %s", st)
	}
	e.idle()
}

func TestShutdownCancelsAndWaits(t *testing.T) {
	t.Parallel()
	e, s := streamEnv(t, 50<<20, true)
	pr := e.prepare(transfer.PrepareRequest{SourceID: "sftp-quick:s", Direction: transfer.Download, Path: "/gen"})
	done := make(chan response, 1)
	go func() { done <- e.do(e.owner, http.MethodGet, pr.URL, nil, 0) }()
	s.gate <- struct{}{}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if err := e.m.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	if r := <-done; !r.aborted {
		t.Fatal("download survived the shutdown")
	}
	if _, err := e.m.Prepare(t.Context(), e.caller(), transfer.PrepareRequest{SourceID: "sftp-quick:s", Direction: transfer.Download, Path: "/gen"}); err == nil {
		t.Fatal("prepare after shutdown")
	}
	e.idle()
}

// heapWatch samples the live heap while f runs and returns the peak
// growth over the start.
func heapWatch(t *testing.T, f func()) uint64 {
	t.Helper()
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	base := ms.HeapAlloc
	var peak atomic.Uint64
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		tick := time.NewTicker(2 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tick.C:
				var m runtime.MemStats
				runtime.ReadMemStats(&m)
				if m.HeapAlloc > base && m.HeapAlloc-base > peak.Load() {
					peak.Store(m.HeapAlloc - base)
				}
			}
		}
	})
	f()
	close(stop)
	wg.Wait()
	return peak.Load()
}

// discard is a ResponseWriter that keeps nothing (the browser).
type discard struct {
	h http.Header
	n int64
}

func (d *discard) Header() http.Header         { return d.h }
func (d *discard) WriteHeader(int)             {}
func (d *discard) Write(p []byte) (int, error) { d.n += int64(len(p)); return len(p), nil }

// TestLargeTransfersDoNotGrowMemory moves 1 GiB each way through the
// handlers. Neither the body nor the file is buffered: the live heap
// stays far below the size of the transfer.
func TestLargeTransfersDoNotGrowMemory(t *testing.T) {
	if testing.Short() {
		t.Skip("moves 2 GiB")
	}
	const size = 1 << 30
	e, s := streamEnv(t, size, false, func(o *transfer.Options) {
		o.Limits = transfer.DefaultLimits
		o.Limits.MaxUpload, o.Limits.MaxDownload = size, size
	})
	pr := e.prepare(transfer.PrepareRequest{SourceID: "sftp-quick:s", Direction: transfer.Download, Path: "/gen"})
	out := &discard{h: http.Header{}}
	down := heapWatch(t, func() {
		req, _ := http.NewRequestWithContext(principal.With(t.Context(), e.owner), http.MethodGet, pr.URL[len("/root"):], nil)
		e.mux.ServeHTTP(out, req)
	})
	if out.n != size {
		t.Fatalf("downloaded %d", out.n)
	}
	pr = e.prepare(transfer.PrepareRequest{SourceID: "sftp-quick:s", Direction: transfer.Upload, Path: "/up"})
	up := heapWatch(t, func() {
		src := &genReader{b: newStream(size), ctx: t.Context()}
		if r := e.do(e.owner, http.MethodPost, pr.URL, src, size); r.Code != 200 {
			t.Errorf("upload %d %s", r.Code, r.Body.String())
		}
	})
	if s.written.Load() != size {
		t.Fatalf("uploaded %d", s.written.Load())
	}
	t.Logf("peak heap growth: download %d KiB, upload %d KiB", down>>10, up>>10)
	const bound = 16 << 20
	if down > bound || up > bound {
		t.Fatalf("heap grew by %d / %d bytes for a 1 GiB transfer", down, up)
	}
	e.idle()
}
