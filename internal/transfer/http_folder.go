package transfer

import (
	"archive/zip"
	"context"
	"io"
	"net/http"
	"path"
	"strings"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/files"
)

// FolderHTTP streams a folder as ZIP (GET /api/transfers/{token}/folder-download).
//
// The Python release built the archive in TRANSFER_TEMP_DIR and sent it
// afterwards. Here it is written to the response while the files are
// read, so no temporary file exists and nothing has to be cleaned up when
// a transfer ends early. The limits are the same: the tree is walked
// first, links, the member and depth limits and the declared size refuse
// the download before any byte is sent; the bytes read and the archive
// written stay within min(MAX_ZIP_DOWNLOAD_SIZE, QUOTA_TEMP_BYTES_PER_USER).
// No disk space is used, so the temp_bytes quota is not charged (TR1-2);
// the transfer quota of the user bounds how many archives run at once.
func (m *Manager) FolderHTTP(w http.ResponseWriter, req *http.Request) {
	r, p, req := m.started(w, req, Download, true)
	if r == nil {
		return
	}
	ctx := req.Context()
	b, release, err := m.o.Sources.Resolve(ctx, p, r.sourceID, files.CapRead|files.CapRecursive)
	if err != nil {
		notFound(w)
		m.end(r, Failed, nil)
		return
	}
	defer release()
	entries, total, err := m.planArchive(ctx, b, r)
	if err != nil {
		f := endedBy(ctx, err, opFolder)
		m.auditOp(r, p.Username, "folder_download", string(f.Code), 0)
		writeFailure(w, f)
		m.end(r, stateOf(f), &f)
		return
	}
	attachment(w, folderName(r.path)+".zip", "application/zip")
	w.WriteHeader(http.StatusOK)
	n, err := m.writeArchive(ctx, w, b, r, entries, total)
	m.closeDownload(ctx, r, p.Username, "folder_download", n, err)
}

// archiveLimit bounds one archive: MAX_ZIP_DOWNLOAD_SIZE, and the
// per-user temp quota of the Python release, which built it on disk. The
// quota is a cap per archive only; it is not reserved.
func (m *Manager) archiveLimit() int64 {
	return min(m.o.Limits.MaxArchive, m.o.Limits.TempBytesPerUse)
}

// planArchive checks the folder and its tree. It returns the entries
// below the folder and their declared size.
func (m *Manager) planArchive(ctx context.Context, b files.Backend, r *record) ([]files.Entry, int64, error) {
	st, err := b.Stat(ctx, r.path, false)
	if err != nil {
		return nil, 0, err
	}
	if !st.IsDir || st.IsSymlink {
		return nil, 0, fault.New(fault.FileNotFound, "")
	}
	limit := m.archiveLimit()
	if limit < 1 {
		return nil, 0, errLimit
	}
	bud := &budget{maxBytes: limit, maxMembers: m.o.Limits.MaxMembers, maxDepth: m.o.Limits.MaxDepth}
	entries, err := bud.tree(ctx, b, r.path)
	if err != nil {
		return nil, 0, err
	}
	var total int64
	for _, e := range entries {
		if !e.IsDir {
			total += e.Size
		}
	}
	return entries, total, nil
}

// folderName is the top directory of the archive.
func folderName(p string) string {
	if b := path.Base(strings.TrimRight(p, "/")); b != "." && b != "/" && b != "" {
		return b
	}
	return "download"
}

// counter counts the bytes written to the response and keeps the
// archive within its limit.
type counter struct {
	w     io.Writer
	c     *conn
	n     int64
	limit int64
}

func (c *counter) Write(p []byte) (int, error) {
	if c.n+int64(len(p)) > c.limit {
		return 0, errLimit
	}
	c.c.beforeWrite()
	k, err := c.w.Write(p)
	c.n += int64(k)
	if err != nil {
		return k, errClientGone
	}
	return k, nil
}

// writeArchive writes the archive (deflate, as the Python release did)
// and returns the bytes of file content it read.
func (m *Manager) writeArchive(ctx context.Context, w http.ResponseWriter, b files.Backend, r *record, entries []files.Entry, total int64) (int64, error) {
	limit := m.archiveLimit()
	out := &counter{w: w, c: m.conn(w), limit: limit}
	zw := zip.NewWriter(out)
	pg := m.progress(r, total)
	defer pg.done()
	root, top := strings.TrimSuffix(r.path, "/")+"/", strings.ReplaceAll(folderName(r.path), `\`, "_")
	buf := make([]byte, m.o.ChunkSize)
	var read int64
	for _, e := range entries {
		if err := ctx.Err(); err != nil {
			return read, err
		}
		// A backslash is an ordinary character of a POSIX name, but a
		// separator to some extractors; it never leaves the folder.
		name := top + "/" + strings.ReplaceAll(strings.TrimPrefix(e.Path, root), `\`, "_")
		if e.IsDir {
			if _, err := zw.CreateHeader(&zip.FileHeader{Name: name + "/", Modified: e.ModTime}); err != nil {
				return read, err
			}
			continue
		}
		n, err := m.archiveFile(ctx, zw, b, e, name, buf, limit-read, func(k int64) { pg.update(read+k, -1, "") })
		read += n
		if err != nil {
			return read, err
		}
	}
	return read, zw.Close()
}

// archiveFile adds one file of at most room bytes.
func (m *Manager) archiveFile(ctx context.Context, zw *zip.Writer, b files.Backend, e files.Entry, name string, buf []byte, room int64, progress func(int64)) (int64, error) {
	rd, err := b.Open(ctx, e.Path, files.Range{Length: -1})
	if err != nil {
		return 0, err
	}
	defer rd.Close()
	if rd.Entry().Size > room {
		return 0, errLimit
	}
	dst, err := zw.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Deflate, Modified: e.ModTime})
	if err != nil {
		return 0, err
	}
	src := &meter{r: io.LimitReader(rd, room+1), ctx: ctx, on: func(int64) {}}
	var n int64
	for {
		k, rerr := src.Read(buf)
		if k > 0 {
			n += int64(k)
			if n > room {
				return n, errLimit
			}
			if _, err := dst.Write(buf[:k]); err != nil {
				return n, err
			}
			progress(n)
		}
		if rerr == io.EOF {
			return n, nil
		}
		if rerr != nil {
			return n, rerr
		}
	}
}
