package smb

import (
	"context"
	"errors"
	"io"
	"sync"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/files"
)

// chunk is the size of one read or write call on the session. The
// library pipelines one call into requests within its credits; the I/O
// idle timeout bounds each call, so a server that stops answering in the
// middle of a transfer fails it after at most that long.
const chunk = 1 << 20

// reader reads one file below held ancestors. Reads end with the context
// Open was called with.
type reader struct {
	b     *Backend
	o     opened
	ent   files.Entry
	left  int64 // bytes left in the range; -1: to the end
	buf   []byte
	start int
	end   int
	ctx   context.Context

	mu     sync.Mutex
	closed bool
}

// Open reads the regular file at p from r.Offset; a directory or a
// reparse point is refused.
func (b *Backend) Open(ctx context.Context, p string, r files.Range) (files.Reader, error) {
	if err := b.alive(); err != nil {
		return nil, err
	}
	if r.Offset < 0 {
		return nil, fault.New(fault.InvalidRequest, "The range is invalid.")
	}
	parts, err := b.mutable(p)
	if err != nil {
		return nil, err
	}
	o, err := b.leaf(ctx, parts, nil, accessRead, fileOpen, shareAll, kindAny)
	if err != nil {
		if isCode(err, fault.SMBReparsePointRejected) {
			return nil, fault.Wrap(fault.UnsupportedOperation, err, "")
		}
		return nil, err
	}
	if o.info.isDir() {
		o.release()
		return nil, fault.New(fault.UnsupportedOperation, "")
	}
	rd := &reader{b: b, o: o, ent: entry(o.info, joinPath(parts)), left: r.Length, ctx: ctx}
	rd.ent.Name = parts[len(parts)-1]
	if r.Length < 0 {
		rd.left = -1
	}
	if r.Offset > 0 {
		if _, err := o.file.Seek(ctx, r.Offset, io.SeekStart); err != nil {
			o.release()
			return nil, b.fileError(ctx, err)
		}
	}
	return rd, nil
}

func (r *reader) Entry() files.Entry { return r.ent }

func (r *reader) Read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return 0, errUnavailable
	}
	if r.left == 0 {
		return 0, io.EOF
	}
	if r.start == r.end {
		if err := r.fill(); err != nil {
			return 0, err
		}
	}
	n := copy(p, r.buf[r.start:r.end])
	if r.left >= 0 && int64(n) > r.left {
		n = int(r.left)
	}
	r.start += n
	if r.left > 0 {
		r.left -= int64(n)
	}
	return n, nil
}

func (r *reader) fill() error {
	if err := r.b.alive(); err != nil {
		return err
	}
	if r.buf == nil {
		r.buf = make([]byte, chunk)
	}
	want := len(r.buf)
	if r.left >= 0 && r.left < int64(want) {
		want = int(r.left)
	}
	ctx, cancel := r.b.op(r.ctx)
	defer cancel()
	n, err := r.o.file.Read(ctx, r.buf[:want])
	r.start, r.end = 0, n
	if n > 0 {
		return nil
	}
	if errors.Is(err, io.EOF) || err == nil {
		r.left = 0
		return io.EOF
	}
	return r.b.fileError(ctx, err)
}

// Close releases the file and its ancestors.
func (r *reader) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.closed {
		r.closed = true
		r.o.release()
	}
	return nil
}
