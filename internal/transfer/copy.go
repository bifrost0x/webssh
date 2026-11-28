package transfer

import (
	"context"
	"io"
	"path"
	"slices"
	"strings"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/files"
)

// budget bounds the bytes and members of one copy or archive
// (TransferBudget in app/remote_transfer.py).
type budget struct {
	maxBytes   int64
	maxMembers int
	maxDepth   int
	used       int64
}

var errLimit = fault.New(fault.LimitExceeded, "")

// declare checks that n more bytes fit before they are read.
func (b *budget) declare(n int64) error {
	if n < 0 || b.used+n > b.maxBytes {
		return errLimit
	}
	return nil
}

// tree walks dir within the budget and returns the entries below it
// (not dir itself), parents first. A link anywhere refuses the copy
// before anything is written, as do the depth limit and declared sizes
// beyond the byte limit.
func (b *budget) tree(ctx context.Context, src files.Backend, dir string) ([]files.Entry, error) {
	var out []files.Entry
	var declared int64
	// Walk counts dir itself as a member; Python's iter_tree did not.
	err := src.Walk(ctx, dir, files.Budget{MaxMembers: b.maxMembers + 1, MaxDepth: b.maxDepth}, func(e files.Entry) error {
		if e.Path == dir {
			return nil
		}
		if e.IsSymlink {
			return errLink
		}
		if !strings.HasPrefix(e.Path, strings.TrimSuffix(dir, "/")+"/") {
			return errUnsafe
		}
		if !e.IsDir {
			declared += e.Size
			if e.Size < 0 || b.used+declared > b.maxBytes {
				return errLimit
			}
		}
		out = append(out, e)
		return nil
	})
	return out, err
}

var (
	errLink   = fault.New(fault.TransferUnavailable, "Reparse points are not supported")
	errUnsafe = fault.New(fault.TransferUnavailable, "Unsafe recursive source path")
	errSame   = fault.New(fault.FileConflict, "Source and destination are identical")
)

// copier copies one entry from src to dst (copy_remote_entry).
type copier struct {
	src, dst         files.Backend
	sameSource, fold bool
	replace          bool
	bud              *budget
	chunk            int
	// progress gets the path of the file, the bytes of the whole copy and
	// the declared size of the file.
	progress func(path string, total, size int64)
	members  int
}

// run copies from to to: a file, or a directory with everything below it.
func (c *copier) run(ctx context.Context, from, to string) error {
	if c.sameSource && (from == to || c.fold && strings.EqualFold(from, to)) {
		return errSame
	}
	st, err := c.src.Stat(ctx, from, false)
	if err != nil {
		return err
	}
	if st.IsSymlink {
		return errLink
	}
	if !st.IsDir {
		c.members = 1
		return c.file(ctx, from, to)
	}
	srcPin, err := pinRoot(ctx, c.src, from)
	if err != nil {
		return err
	}
	entries, err := c.bud.tree(ctx, c.src, from)
	if err != nil {
		return err
	}
	if err := c.directory(ctx, to, c.replace); err != nil {
		return err
	}
	dstPin, err := pinRoot(ctx, c.dst, to)
	if err != nil {
		return err
	}
	prefix := strings.TrimSuffix(from, "/") + "/"
	dest := func(e files.Entry) string {
		return strings.TrimSuffix(to, "/") + "/" + strings.TrimPrefix(e.Path, prefix)
	}
	// Directories first, shallow before deep.
	dirs := slices.DeleteFunc(slices.Clone(entries), func(e files.Entry) bool { return !e.IsDir })
	slices.SortStableFunc(dirs, func(a, b files.Entry) int { return strings.Count(a.Path, "/") - strings.Count(b.Path, "/") })
	for _, e := range dirs {
		if err := dstPin.check(ctx, path.Dir(dest(e))); err != nil {
			return err
		}
		if err := c.directory(ctx, dest(e), true); err != nil {
			return err
		}
	}
	c.members = len(entries)
	for _, e := range entries {
		if e.IsDir {
			continue
		}
		if err := srcPin.check(ctx, path.Dir(e.Path)); err != nil {
			return err
		}
		if err := dstPin.check(ctx, path.Dir(dest(e))); err != nil {
			return err
		}
		if err := c.file(ctx, e.Path, dest(e)); err != nil {
			return err
		}
	}
	return nil
}

// pin is the canonical form of a copy root on its backend (Stat with
// follow resolves links: REALPATH on SFTP). Requests name paths and the
// server resolves links in their directories, so a local user may replace
// a directory of either tree by a link while the copy runs. Before a
// file is read or written, and before a directory is created, its
// directory must still resolve to the root's canonical path plus the
// relative path. The writer and the walk check again inside their own
// steps; one round trip between check and request remains.
type pin struct {
	b          files.Backend
	root, real string
}

func pinRoot(ctx context.Context, b files.Backend, root string) (pin, error) {
	e, err := b.Stat(ctx, root, true)
	if err != nil {
		return pin{}, err
	}
	return pin{b: b, root: strings.TrimSuffix(root, "/"), real: e.Path}, nil
}

func (p pin) check(ctx context.Context, dir string) error {
	want := p.real
	if dir != p.root && dir != "/" {
		want = path.Join(p.real, strings.TrimPrefix(dir, p.root+"/"))
	}
	e, err := p.b.Stat(ctx, dir, true)
	if err != nil {
		return err
	}
	if e.Path != want || !e.IsDir {
		return fault.New(fault.SourceChanged, "")
	}
	return nil
}

// directory makes sure p is a directory of dst: an existing one is kept
// when allowed, anything else at p is a conflict (_ensure_directory).
func (c *copier) directory(ctx context.Context, p string, allowExisting bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	e, err := c.dst.Stat(ctx, p, false)
	switch {
	case err == nil && e.IsDir && !e.IsSymlink && allowExisting:
		return nil
	case err == nil:
		return fault.New(fault.FileConflict, "")
	case !fault.Is(err, fault.FileNotFound):
		return err
	}
	return c.dst.Mkdir(ctx, p)
}

// file streams one regular file through the destination's atomic writer.
func (c *copier) file(ctx context.Context, from, to string) error {
	rd, err := c.src.Open(ctx, from, files.Range{Length: -1})
	if err != nil {
		return err
	}
	defer rd.Close()
	size := rd.Entry().Size
	if err := c.bud.declare(size); err != nil {
		return err
	}
	src := &meter{r: rd, ctx: ctx, on: func(n int64) {
		c.bud.used += n
		if c.progress != nil {
			c.progress(from, c.bud.used, size)
		}
	}}
	_, err = c.dst.Write(ctx, to, bufReader(src, c.chunk), files.WriteOptions{
		Exclusive: !c.replace, Strategy: files.StrategyAtomic, Size: size,
	})
	if err != nil {
		return err
	}
	return ctx.Err()
}

// meter counts what passes through r and stops when ctx ends.
type meter struct {
	r   io.Reader
	ctx context.Context
	on  func(n int64)
}

func (m *meter) Read(p []byte) (int, error) {
	if err := m.ctx.Err(); err != nil {
		return 0, err
	}
	n, err := m.r.Read(p)
	if n > 0 {
		m.on(int64(n))
	}
	return n, err
}

// bufReader bounds the reads of a writer that asks for more at once.
func bufReader(r io.Reader, chunk int) io.Reader { return &chunked{r: r, n: chunk} }

type chunked struct {
	r io.Reader
	n int
}

func (c *chunked) Read(p []byte) (int, error) {
	if len(p) > c.n {
		p = p[:c.n]
	}
	return c.r.Read(p)
}
