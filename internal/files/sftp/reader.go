package sftp

import (
	"context"
	"errors"
	"io"
	"os"
	"path"
	"sync"
	"time"

	pkgsftp "github.com/pkg/sftp"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/files"
)

// await runs fn, a pkg/sftp call without a context, and returns when it
// finishes or ctx ends. The call itself ends within the operation timeout
// (router watchdog); a result that arrives after ctx ended is given to
// discard.
func await[T any](ctx context.Context, fn func() (T, error), discard func(T)) (T, error) {
	type result struct {
		v   T
		err error
	}
	got := make(chan result, 1)
	go func() {
		v, err := fn()
		got <- result{v, err}
	}()
	select {
	case r := <-got:
		return r.v, r.err
	case <-ctx.Done():
		go func() {
			if r := <-got; r.err == nil && discard != nil {
				discard(r.v)
			}
		}()
		var zero T
		return zero, &transportError{sent: true, err: ctx.Err()}
	}
}

func closeFile(f *pkgsftp.File) { _ = f.Close() }

// openFile opens p with flags through pkg/sftp within ctx.
func (b *Backend) openFile(ctx context.Context, p string, flags int) (*pkgsftp.File, error) {
	return await(ctx, func() (*pkgsftp.File, error) { return b.lib.OpenFile(p, flags) }, closeFile)
}

// fstat reads the attributes of an open file (SSH_FXP_FSTAT).
func (b *Backend) fstat(ctx context.Context, f *pkgsftp.File) (*pkgsftp.FileStat, error) {
	fi, err := await(ctx, f.Stat, nil)
	if err != nil {
		return nil, err
	}
	st, ok := fi.Sys().(*pkgsftp.FileStat)
	if !ok {
		return nil, fault.New(fault.OperationFailed, msgInvalidReply)
	}
	return st, nil
}

func entryOfStat(p string, st *pkgsftp.FileStat) files.Entry {
	return entryOf(p, path.Base(p), attrs{
		flags: attrSize | attrUIDGID | attrPermissions | attrACModTime,
		size:  st.Size, uid: st.UID, gid: st.GID, mode: st.Mode, mtime: st.Mtime,
	})
}

// Open implements files.Backend. The object at path must be a regular
// file (lstat, so a link is refused); what is read is described by FSTAT
// on the opened handle. Reads keep Prefetch requests in flight.
//
// ctx bounds the opening. Reads are bounded by the operation timeout and
// end with Close.
func (b *Backend) Open(ctx context.Context, p string, r files.Range) (files.Reader, error) {
	if r.Offset < 0 {
		return nil, fault.New(fault.InvalidRequest, "")
	}
	ctx, cancel, err := b.begin(ctx, false)
	if err != nil {
		return nil, err
	}
	defer cancel()
	a, err := b.w.lstat(ctx, p)
	if err != nil {
		return nil, b.mapErr(err, false)
	}
	if !isRegular(a.mode) {
		return nil, fault.New(fault.UnsupportedOperation, "")
	}
	f, err := b.openFile(ctx, p, os.O_RDONLY)
	if err != nil {
		return nil, b.mapErr(err, false)
	}
	st, err := b.fstat(ctx, f)
	if err != nil {
		closeFile(f)
		return nil, b.mapErr(err, false)
	}
	if !isRegular(st.Mode) {
		closeFile(f)
		return nil, fault.New(fault.UnsupportedOperation, "")
	}
	end := int64(-1)
	if r.Length >= 0 {
		end = r.Offset + r.Length
	}
	return newPrefetch(b, f, entryOfStat(p, st), r.Offset, end), nil
}

// chunk is one read request of the prefetch.
type chunk struct {
	buf  []byte
	n    int
	err  error
	done chan struct{}
}

// prefetch reads a file in chunks with a window of requests in flight, in
// order. The Python release read one request at a time (4.9 MiB/s in the
// baseline).
type prefetch struct {
	b     *Backend
	f     *pkgsftp.File
	entry files.Entry

	next int64 // offset of the next request
	end  int64 // -1: to the end of the file
	size int   // bytes per request

	queue []*chunk // in flight, in file order
	cur   *chunk   // being consumed
	pos   int
	free  [][]byte
	eof   bool // a request reached the end; send no more
	err   error

	mu     sync.Mutex
	closed bool
	wg     sync.WaitGroup
}

func newPrefetch(b *Backend, f *pkgsftp.File, e files.Entry, off, end int64) *prefetch {
	p := &prefetch{b: b, f: f, entry: e, next: off, end: end, size: b.chunk}
	p.fillWindow()
	return p
}

func (p *prefetch) Entry() files.Entry { return p.entry }

// fillWindow sends requests until Prefetch are in flight.
func (p *prefetch) fillWindow() {
	for len(p.queue) < p.b.o.Prefetch && !p.eof && (p.end < 0 || p.next < p.end) {
		n := int64(p.size)
		if p.end >= 0 {
			n = min(n, p.end-p.next)
		}
		var buf []byte
		if k := len(p.free); k > 0 {
			buf, p.free = p.free[k-1], p.free[:k-1]
		} else {
			buf = make([]byte, p.size)
		}
		c := &chunk{buf: buf[:n], done: make(chan struct{})}
		off := p.next
		p.next += n
		p.queue = append(p.queue, c)
		p.wg.Go(func() {
			defer close(c.done)
			c.n, c.err = p.f.ReadAt(c.buf, off)
		})
	}
}

// Read implements io.Reader.
func (p *prefetch) Read(b []byte) (int, error) {
	for p.cur == nil || p.pos == p.cur.n {
		if p.cur != nil {
			if p.cur.n < len(p.cur.buf) || p.cur.err != nil {
				// A short chunk ends the file: what follows was read past it.
				p.eof = true
				p.queue = nil
			}
			p.free = append(p.free, p.cur.buf[:cap(p.cur.buf)])
			p.cur = nil
		}
		if p.err != nil {
			return 0, p.err
		}
		p.fillWindow()
		if len(p.queue) == 0 {
			p.err = io.EOF
			return 0, io.EOF
		}
		c := p.queue[0]
		p.queue = p.queue[1:]
		if err := p.wait(c); err != nil {
			p.err = err
			return 0, err
		}
		if c.err != nil && !errors.Is(c.err, io.EOF) {
			p.err = p.b.mapErr(c.err, false)
		}
		p.cur, p.pos = c, 0
	}
	n := copy(b, p.cur.buf[p.pos:p.cur.n])
	p.pos += n
	return n, nil
}

// wait waits for c. The router's watchdog ends a request that the server
// does not answer; the timer is the guard against a closed reader.
func (p *prefetch) wait(c *chunk) error {
	t := time.NewTimer(p.b.o.OperationTimeout + time.Second)
	defer t.Stop()
	select {
	case <-c.done:
		return nil
	case <-t.C:
		return fault.New(fault.FileTimeout, "")
	}
}

// WriteTo implements io.WriterTo so io.Copy uses the chunk buffers
// directly.
func (p *prefetch) WriteTo(w io.Writer) (int64, error) {
	var total int64
	for {
		if p.cur == nil || p.pos == p.cur.n {
			if _, err := p.Read(nil); err != nil {
				if errors.Is(err, io.EOF) {
					return total, nil
				}
				return total, err
			}
			if p.cur == nil || p.pos == p.cur.n {
				continue
			}
		}
		n, err := w.Write(p.cur.buf[p.pos:p.cur.n])
		p.pos += n
		total += int64(n)
		if err != nil {
			return total, err
		}
	}
}

// Close implements io.Closer: it waits for the requests in flight and
// closes the handle.
func (p *prefetch) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	p.closed = true
	p.wg.Wait()
	ctx, cancel := context.WithTimeout(context.Background(), p.b.o.OperationTimeout)
	defer cancel()
	_, err := await(ctx, func() (struct{}, error) { return struct{}{}, p.f.Close() }, nil)
	if err != nil && !answered(err) {
		return p.b.mapErr(err, false)
	}
	return nil
}
