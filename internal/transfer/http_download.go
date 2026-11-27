package transfer

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/files"
)

// DownloadHTTP streams one file (GET /api/transfers/{token}/download).
// The body is the file as it was opened: Content-Length is its size, and
// fewer bytes end the response early with SOURCE_CHANGED.
func (m *Manager) DownloadHTTP(w http.ResponseWriter, req *http.Request) {
	r, p, req := m.started(w, req, Download, false)
	if r == nil {
		return
	}
	ctx := req.Context()
	b, release, err := m.o.Sources.Resolve(ctx, p, r.sourceID, files.CapRead)
	if err != nil {
		notFound(w)
		m.end(r, Failed, nil)
		return
	}
	defer release()
	rd, err := b.Open(ctx, r.path, files.Range{Length: -1})
	if err != nil {
		if fault.Is(err, fault.UnsupportedOperation) {
			err = fault.New(fault.FileNotFound, "") // a folder or a link (FolderUnavailable)
		}
		f := endedBy(ctx, err, opDownload)
		m.auditOp(r, p.Username, "download", string(f.Code), 0)
		writeFailure(w, f)
		m.end(r, stateOf(f), &f)
		return
	}
	defer rd.Close()
	size := rd.Entry().Size
	if size > m.o.Limits.MaxDownload {
		f := limitFailure(LimitDownload, m.o.Limits.MaxDownload, size)
		m.auditOp(r, p.Username, "download", string(f.Code), size)
		writeFailure(w, f)
		m.end(r, Failed, &f)
		return
	}
	attachment(w, baseName(r.path), "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	w.WriteHeader(http.StatusOK)
	n, err := m.stream(ctx, w, rd, r, size)
	if err == nil && n < size {
		err = fault.New(fault.SourceChanged, "")
	}
	m.closeDownload(ctx, r, p.Username, "download", n, err)
}

// stream copies src to the response in chunks, extending the write
// deadline per chunk and sending throttled progress. It stops at limit
// bytes.
func (m *Manager) stream(ctx context.Context, w http.ResponseWriter, src io.Reader, r *record, limit int64) (int64, error) {
	c := m.conn(w)
	pg := m.progress(r, limit)
	defer pg.done()
	buf := make([]byte, m.o.ChunkSize)
	var n int64
	for n < limit {
		if err := ctx.Err(); err != nil {
			return n, err
		}
		k, rerr := src.Read(buf[:min(int64(len(buf)), limit-n)])
		if k > 0 {
			c.beforeWrite()
			if _, err := w.Write(buf[:k]); err != nil {
				return n, errClientGone
			}
			n += int64(k)
			pg.update(n, -1, "")
		}
		if errors.Is(rerr, io.EOF) {
			return n, nil
		}
		if rerr != nil {
			return n, rerr
		}
	}
	return n, nil
}

// errClientGone is a browser that stopped reading: the transfer counts as
// cancelled, as a closed Python response did (GeneratorExit).
var errClientGone = fault.New(fault.FileCancelled, "")

// closeDownload ends a download whose headers are sent. A failure aborts
// the connection, so the browser never keeps a truncated file as
// complete.
func (m *Manager) closeDownload(ctx context.Context, r *record, user, op string, n int64, err error) {
	if err == nil {
		m.auditOp(r, user, op, "COMPLETED", n)
		m.end(r, Completed, nil)
		return
	}
	f := endedBy(ctx, err, operation(op))
	if errors.Is(err, errClientGone) {
		f = newFailure(fault.FileCancelled, operation(op))
	}
	m.o.Logger.Info("download ended early", "user_id", r.owner.userID, "transfer_id", r.id, "code", string(f.Code))
	m.auditOp(r, user, op, string(f.Code), n)
	m.end(r, stateOf(f), &f)
	panic(http.ErrAbortHandler)
}

// stateOf is the final state of a transfer that failed with f.
func stateOf(f Failure) State {
	if f.Code == fault.FileCancelled {
		return Cancelled
	}
	return Failed
}
