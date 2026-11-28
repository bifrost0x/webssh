package sftp

import (
	"context"
	"path"
	"strings"
	"sync"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/files"
)

// metaBudget charges the server-controlled bytes of a listing or a tree
// operation, as _TransferMemberBudget of the Python release: every entry
// counts, also "." and "..", with its name, long name, attribute
// extensions and 128 bytes.
type metaBudget struct {
	members, maxMembers int
	bytes, maxBytes     int
}

func (m *metaBudget) charge(e nameEntry) error {
	m.members++
	if m.members > m.maxMembers {
		return fault.New(fault.LimitExceeded, msgMemberLimit)
	}
	m.bytes += len(e.name) + e.longname + e.attrs.extensions + 128
	if m.bytes > m.maxBytes {
		return fault.New(fault.LimitExceeded, msgMetadataLimit)
	}
	return nil
}

// request bounds one request of a longer operation.
func (b *Backend) request(ctx context.Context, mutation bool) (context.Context, context.CancelFunc) {
	if mutation {
		return context.WithTimeout(ctx, b.o.MutationTimeout)
	}
	return context.WithTimeout(ctx, b.o.OperationTimeout)
}

// dirReader pages through one open directory handle.
type dirReader struct {
	b      *Backend
	dir    string
	handle string
	buf    []nameEntry
	eof    bool
	budget *metaBudget
	strict bool // tree operations: names must pass strictName
}

func (b *Backend) openDir(ctx context.Context, dir string, budget *metaBudget, strict bool) (*dirReader, error) {
	rctx, cancel := b.request(ctx, false)
	defer cancel()
	h, err := b.w.opendir(rctx, dir)
	if err != nil {
		return nil, b.mapErr(err, false)
	}
	return &dirReader{b: b, dir: dir, handle: h, budget: budget, strict: strict}, nil
}

// fill reads the next batch when the buffer is empty.
func (d *dirReader) fill(ctx context.Context) error {
	for len(d.buf) == 0 && !d.eof {
		rctx, cancel := d.b.request(ctx, false)
		batch, eof, err := d.b.w.readdir(rctx, d.handle)
		cancel()
		if err != nil {
			return d.b.mapErr(err, false)
		}
		d.eof = eof
		for _, e := range batch {
			if err := d.budget.charge(e); err != nil {
				return err
			}
			if e.name == "." || e.name == ".." {
				continue
			}
			if e.name == "" || strings.ContainsAny(e.name, "/\x00") || d.strict && !strictName(e.name) {
				return fault.New(fault.OperationFailed, msgUnsafeName)
			}
			// A tree operation never holds a path the file layer could not
			// address (files.Clean): the budget counts names, not paths.
			if d.strict && len(d.dir)+1+len(e.name) > files.MaxPathBytes {
				return fault.New(fault.OperationFailed, msgUnsafeName)
			}
			d.buf = append(d.buf, e)
		}
	}
	return nil
}

func (d *dirReader) take(ctx context.Context, max int) ([]nameEntry, error) {
	var out []nameEntry
	for len(out) < max {
		if err := d.fill(ctx); err != nil {
			return nil, err
		}
		if len(d.buf) == 0 {
			break
		}
		n := min(max-len(out), len(d.buf))
		out = append(out, d.buf[:n]...)
		d.buf = d.buf[n:]
	}
	return out, nil
}

func (d *dirReader) close() {
	if d.handle == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), d.b.o.OperationTimeout)
	defer cancel()
	if err := d.b.w.closeHandle(ctx, d.handle); err != nil && !answered(err) {
		// A handle whose close is not confirmed may stay open on the
		// server; the channel goes with it, as in the Python release.
		d.b.r.fail(errClosed)
	}
	d.handle = ""
}

func (d *dirReader) entry(e nameEntry) files.Entry {
	return entryOf(path.Join(d.dir, e.name), e.name, e.attrs)
}

// listing is a files.Listing: one directory handle continued across pages.
type listing struct {
	mu     sync.Mutex
	d      *dirReader
	closed bool
}

// OpenListing implements files.Backend. Pages are read from the open
// handle on demand; the whole directory is never held (the paging of
// app/sftp_handler.py). A name that is not valid UTF-8 is listed but
// cannot be opened (files.Clean refuses it).
func (b *Backend) OpenListing(ctx context.Context, p string) (files.Listing, error) {
	if b.r.cause() != nil {
		return nil, fault.New(fault.SourceUnavailable, "")
	}
	budget := &metaBudget{maxMembers: b.o.maxMembers(), maxBytes: b.o.MaxMetadataBytes}
	d, err := b.openDir(ctx, p, budget, false)
	if err != nil {
		return nil, err
	}
	return &listing{d: d}, nil
}

// Next implements files.Listing. more is exact: a page that ends the
// directory reports false.
func (l *listing) Next(ctx context.Context, max int) ([]files.Entry, bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed || l.d.b.r.cause() != nil {
		return nil, false, fault.New(fault.SourceUnavailable, "")
	}
	if max <= 0 {
		return nil, false, fault.New(fault.InvalidRequest, "")
	}
	batch, err := l.d.take(ctx, max)
	if err == nil {
		err = l.d.fill(ctx)
	}
	if err != nil {
		l.closeLocked()
		return nil, false, err
	}
	out := make([]files.Entry, len(batch))
	for i, e := range batch {
		out[i] = l.d.entry(e)
	}
	more := len(l.d.buf) > 0
	if !more {
		l.closeLocked()
	}
	return out, more, nil
}

// Close implements files.Listing.
func (l *listing) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closeLocked()
	return nil
}

func (l *listing) closeLocked() {
	if !l.closed {
		l.closed = true
		l.d.close()
	}
}

// readAll reads a whole directory for a tree operation; the budget bounds
// it.
func (b *Backend) readAll(ctx context.Context, dir string, budget *metaBudget) ([]files.Entry, error) {
	d, err := b.openDir(ctx, dir, budget, true)
	if err != nil {
		return nil, err
	}
	defer d.close()
	var out []files.Entry
	for {
		batch, err := d.take(ctx, 256)
		if err != nil {
			return nil, err
		}
		if len(batch) == 0 {
			return out, nil
		}
		for _, e := range batch {
			ent := d.entry(e)
			if !e.attrs.has(attrPermissions) {
				// Without a mode in the reply the type is unknown: ask.
				rctx, cancel := b.request(ctx, false)
				a, err := b.w.lstat(rctx, ent.Path)
				cancel()
				if err != nil {
					return nil, b.mapErr(err, false)
				}
				ent = entryOf(ent.Path, ent.Name, a)
			}
			out = append(out, ent)
		}
	}
}

func (o Options) maxMembers() int {
	if o.MaxMembers > 0 {
		return o.MaxMembers
	}
	return files.DefaultMaxMembers
}
