package sftp

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"maps"
	"path"
	"sync"
	"time"
	"unicode/utf8"

	pkgsftp "github.com/pkg/sftp"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/files"
)

// Backend is a files.Backend on one SFTP channel. It is safe for
// concurrent use: requests of different callers are in flight at the same
// time (W-043 of the Python release dropped).
type Backend struct {
	r     *router
	w     wire
	lib   *pkgsftp.Client
	o     Options
	caps  files.Capabilities
	chunk int

	// onClose runs once after the channel closed (Quick SFTP closes its
	// connection and releases its quota there).
	onClose func()
	once    sync.Once
}

// Open starts SFTP on ch, the data stream of the SFTP subsystem
// (client.Conn.Subsystem), and probes what the server supports. The
// backend owns ch from then on; on error ch is closed.
func Open(ctx context.Context, ch io.ReadWriteCloser, o Options) (*Backend, error) {
	o = o.withDefaults()
	r := newRouter(ch, limits{maxName: o.MaxNameBytes, maxHandle: o.MaxHandleBytes, maxMetadata: o.MaxMetadataBytes},
		o.MaxPacketBytes, o.OperationTimeout)
	b := &Backend{r: r, w: wire{r}, o: o}
	ctx, cancel := context.WithTimeout(ctx, o.OperationTimeout)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { r.fail(ctx.Err()) })
	type result struct {
		c   *pkgsftp.Client
		err error
	}
	got := make(chan result, 1)
	go func() {
		// Requests carry one chunk at most; the prefetch and the
		// concurrent writes keep o.Prefetch of them in flight.
		c, err := pkgsftp.NewClientPipe(lib{r}, lib{r},
			pkgsftp.MaxPacketUnchecked(o.ChunkBytes),
			pkgsftp.UseConcurrentReads(true),
			pkgsftp.UseConcurrentWrites(true),
			pkgsftp.UseFstat(true),
			pkgsftp.MaxConcurrentRequestsPerFile(o.Prefetch),
		)
		got <- result{c, err}
	}()
	res := <-got
	if !stop() || res.err != nil {
		if res.c != nil {
			_ = res.c.Close()
		}
		r.close()
		err := res.err
		if err == nil {
			err = ctx.Err()
		}
		return nil, b.mapErr(&transportError{sent: true, err: errors.Join(err, ctx.Err())}, false)
	}
	b.lib = res.c
	b.chunk = o.ChunkBytes
	if lim, err := b.w.limits(ctx); err == nil {
		// limits@openssh.com: never ask for more than the server reads or
		// writes in one request.
		for _, v := range []uint64{lim.read, lim.write} {
			if v > 0 && v < uint64(b.chunk) { // #nosec G115 -- chunk is positive (withDefaults)
				b.chunk = int(v) // #nosec G115 -- v is below chunk, an int
			}
		}
	} else if b.r.cause() != nil {
		_ = b.Close()
		return nil, b.mapErr(err, false)
	}
	b.caps = b.capabilities()
	return b, nil
}

func (b *Backend) capabilities() files.Capabilities {
	ext := b.r.extensions()
	c := files.Capabilities{Ops: files.CapAll, SymlinkTargets: true, RootWritable: true}
	if ext[extPosixRename] == "1" {
		c.Replace = []files.Strategy{files.StrategyAtomic}
	}
	if b.o.ChmodEnabled && ext[extLsetstat] == "1" {
		c.Ops |= files.CapChmod
	}
	return c
}

// Capabilities implements files.Backend.
func (b *Backend) Capabilities() files.Capabilities { return b.caps }

// Extensions returns the extensions the server announced (name to data).
func (b *Backend) Extensions() map[string]string {
	return maps.Clone(b.r.extensions())
}

// Done is closed when the channel ended, by Close or by a failure.
func (b *Backend) Done() <-chan struct{} { return b.r.done }

// Close implements files.Backend. Listings and readers on the backend
// fail from then on.
func (b *Backend) Close() error {
	b.once.Do(func() {
		b.r.close()
		if b.lib != nil {
			_ = b.lib.Close()
		}
		if b.onClose != nil {
			b.onClose()
		}
	})
	return nil
}

// begin checks the backend and ctx before an operation and bounds it.
func (b *Backend) begin(ctx context.Context, mutation bool) (context.Context, context.CancelFunc, error) {
	if b.r.cause() != nil {
		return nil, nil, fault.New(fault.SourceUnavailable, "")
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, b.mapErr(err, false)
	}
	bound := b.o.OperationTimeout
	if mutation {
		bound = b.o.MutationTimeout
	}
	c, cancel := context.WithTimeout(ctx, bound)
	return c, cancel, nil
}

// Home implements files.Backend: the login directory.
func (b *Backend) Home(ctx context.Context) (string, error) {
	ctx, cancel, err := b.begin(ctx, false)
	if err != nil {
		return "", err
	}
	defer cancel()
	p, err := b.w.resolve(ctx, ".")
	if err != nil {
		return "", b.mapErr(err, false)
	}
	clean, err := files.Clean(p)
	if err != nil {
		return "/", nil
	}
	return clean, nil
}

// Stat implements files.Backend.
func (b *Backend) Stat(ctx context.Context, p string, follow bool) (files.Entry, error) {
	ctx, cancel, err := b.begin(ctx, false)
	if err != nil {
		return files.Entry{}, err
	}
	defer cancel()
	stat := b.w.lstat
	if follow {
		stat = b.w.stat
	}
	a, err := stat(ctx, p)
	if err != nil {
		return files.Entry{}, b.mapErr(err, false)
	}
	return entryOf(p, path.Base(p), a), nil
}

// Mkdir implements files.Backend.
func (b *Backend) Mkdir(ctx context.Context, p string) error {
	ctx, cancel, err := b.begin(ctx, true)
	if err != nil {
		return err
	}
	defer cancel()
	err = b.w.mkdir(ctx, p)
	if isStatus(err, fxFailure) && b.exists(ctx, p) {
		return fault.New(fault.FileConflict, "")
	}
	return b.mapErr(err, true)
}

// exists reports whether p exists (lstat); unknown counts as no.
func (b *Backend) exists(ctx context.Context, p string) bool {
	_, err := b.w.lstat(ctx, p)
	return err == nil
}

// Rename implements files.Backend: never replacing, as SSH_FXP_RENAME on
// OpenSSH and the Python release.
func (b *Backend) Rename(ctx context.Context, from, to string) error {
	ctx, cancel, err := b.begin(ctx, true)
	if err != nil {
		return err
	}
	defer cancel()
	if from == to || files.Within(from, to, false) {
		return fault.New(fault.InvalidRequest, "")
	}
	if _, err := b.w.lstat(ctx, from); err != nil {
		return b.mapErr(err, false)
	}
	if b.exists(ctx, to) {
		return fault.New(fault.FileConflict, "")
	}
	err = b.w.rename(ctx, from, to)
	if isStatus(err, fxFailure) && b.exists(ctx, to) {
		return fault.New(fault.FileConflict, "")
	}
	return b.mapErr(err, true)
}

// Chmod implements files.Backend. It needs lsetstat@openssh.com, so the
// mode of a link target never changes: the object at path is checked with
// lstat before (no link, no set-id or sticky bits) and after the change.
func (b *Backend) Chmod(ctx context.Context, p string, perm fs.FileMode) error {
	if !b.caps.Ops.Has(files.CapChmod) {
		return fault.New(fault.UnsupportedOperation, "")
	}
	if perm&^fs.ModePerm != 0 {
		return fault.New(fault.InvalidRequest, "")
	}
	ctx, cancel, err := b.begin(ctx, true)
	if err != nil {
		return err
	}
	defer cancel()
	before, err := b.w.lstat(ctx, p)
	if err != nil {
		return b.mapErr(err, false)
	}
	if !before.has(attrPermissions) || !isRegular(before.mode) && !isDir(before.mode) || before.mode&0o7000 != 0 {
		return fault.New(fault.UnsupportedOperation, "")
	}
	want := uint32(perm.Perm())
	if before.mode&0o777 == want {
		return nil
	}
	if err := b.w.lsetstat(ctx, p, want); err != nil {
		return b.mapErr(err, true)
	}
	after, err := b.w.lstat(ctx, p)
	if err != nil {
		return fault.Wrap(fault.OutcomeUnknown, err, "")
	}
	if after.mode&0o7777 != want || after.mode&0o170000 != before.mode&0o170000 {
		return fault.New(fault.ModeMismatch, "")
	}
	return nil
}

// File type bits of st_mode.
const (
	modeType    = 0o170000
	modeDir     = 0o040000
	modeRegular = 0o100000
	modeLink    = 0o120000
)

func isDir(m uint32) bool     { return m&modeType == modeDir }
func isRegular(m uint32) bool { return m&modeType == modeRegular }
func isLink(m uint32) bool    { return m&modeType == modeLink }

func entryOf(p, name string, a attrs) files.Entry {
	e := files.Entry{
		Name: name, Path: p, Size: int64(min(a.size, 1<<63-1)), Mode: a.mode,
		IsDir: isDir(a.mode), IsSymlink: isLink(a.mode),
	}
	if a.has(attrACModTime) {
		e.ModTime = time.Unix(int64(a.mtime), 0).UTC()
	}
	if a.has(attrUIDGID) {
		e.Owner = &files.Owner{UID: a.uid, GID: a.gid}
	}
	return e
}

// strictName is the rule for names a tree operation descends into: one
// valid UTF-8 component without slash, backslash or NUL (Python
// _is_safe_transfer_entry_name).
func strictName(n string) bool {
	if n == "" || n == "." || n == ".." || !utf8.ValidString(n) {
		return false
	}
	for i := range len(n) {
		if c := n[i]; c == '/' || c == '\\' || c == 0 {
			return false
		}
	}
	return true
}

var _ files.Backend = (*Backend)(nil)
