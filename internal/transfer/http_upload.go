package transfer

import (
	"context"
	"io"
	"net/http"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/files"
)

// UploadHTTP streams the raw request body into the target through the
// source's atomic writer (POST /api/transfers/{token}/upload). The body
// needs a Content-Length of at most MAX_UPLOAD_SIZE; it is never held in
// memory, and a write that does not complete leaves the target as it was.
// The edge must not buffer the body of this route.
func (m *Manager) UploadHTTP(w http.ResponseWriter, req *http.Request) {
	r, p, req := m.started(w, req, Upload, false)
	if r == nil {
		return
	}
	ctx := req.Context()
	size := req.ContentLength
	if size < 0 || size > m.o.Limits.MaxUpload {
		f := limitFailure(LimitUpload, m.o.Limits.MaxUpload, size)
		m.auditOp(r, p.Username, "upload", string(f.Code), 0)
		w.Header().Set("Connection", "close")
		writeFailure(w, f)
		m.end(r, Failed, &f)
		return
	}
	b, release, err := m.o.Sources.Resolve(ctx, p, r.sourceID, files.CapWrite)
	if err != nil {
		notFound(w)
		m.end(r, Failed, nil)
		return
	}
	defer release()
	c := m.conn(w)
	pg := m.progress(r, size)
	body := &bodyReader{r: req.Body, c: c, ctx: ctx, on: func(n int64) { pg.update(n, -1, "") }}
	_, err = b.Write(ctx, r.path, bufReader(body, m.o.ChunkSize), files.WriteOptions{
		Exclusive: r.policy != ConflictReplace, Strategy: files.StrategyAtomic, Size: size, MaxBytes: m.o.Limits.MaxUpload,
	})
	if err == nil {
		err = ctx.Err()
	}
	pg.done()
	if err != nil {
		f := endedBy(ctx, err, opUpload)
		if body.err != nil && ctx.Err() == nil {
			// The browser stopped sending: nothing was installed.
			f = newFailure(fault.FileCancelled, opUpload)
		}
		if f.Code == fault.LimitExceeded {
			f = limitFailure(LimitUpload, m.o.Limits.MaxUpload, -1)
		}
		m.auditOp(r, p.Username, "upload", string(f.Code), body.n)
		w.Header().Set("Connection", "close")
		writeFailure(w, f)
		m.end(r, stateOf(f), &f)
		return
	}
	m.auditOp(r, p.Username, "upload", "COMPLETED", body.n)
	m.end(r, Completed, nil)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.WriteString(w, `{"success":true}`)
}

// bodyReader reads the request body with a read deadline per chunk and
// stops when the transfer is cancelled. A read error of the body itself
// is kept apart from the errors of the destination.
type bodyReader struct {
	r   io.Reader
	c   *conn
	ctx context.Context
	on  func(n int64)
	n   int64
	err error
}

func (b *bodyReader) Read(p []byte) (int, error) {
	if err := b.ctx.Err(); err != nil {
		return 0, err
	}
	b.c.beforeRead()
	k, err := b.r.Read(p)
	b.n += int64(k)
	if k > 0 {
		b.on(b.n)
	}
	if err != nil && err != io.EOF {
		b.err = err
	}
	return k, err
}
