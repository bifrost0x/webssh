package sftp

import (
	"context"
	"path"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/files"
)

// tree is the state of one Walk or recursive Remove.
type tree struct {
	b      *Backend
	bud    files.Budget
	meta   *metaBudget
	visits int
	bytes  int64
}

func (b *Backend) newTree(bud files.Budget) *tree {
	bud = bud.WithDefaults()
	return &tree{b: b, bud: bud, meta: &metaBudget{
		// The member count of the budget is checked per visit; the
		// metadata budget also counts what the server sends.
		maxMembers: max(bud.MaxMembers, b.o.maxMembers()) + 2*bud.MaxMembers,
		maxBytes:   b.o.MaxMetadataBytes,
	}}
}

func (t *tree) visit(e files.Entry, depth int) error {
	t.visits++
	if !e.IsDir {
		t.bytes += e.Size
	}
	switch {
	case t.visits > t.bud.MaxMembers:
		return fault.New(fault.LimitExceeded, msgMemberLimit)
	case depth > t.bud.MaxDepth:
		return fault.New(fault.LimitExceeded, msgDepthLimit)
	case t.bud.MaxBytes > 0 && t.bytes > t.bud.MaxBytes:
		return fault.New(fault.LimitExceeded, "")
	}
	return nil
}

func (b *Backend) rootEntry(ctx context.Context, p string) (files.Entry, error) {
	rctx, cancel := b.request(ctx, false)
	defer cancel()
	a, err := b.w.lstat(rctx, p)
	if err != nil {
		return files.Entry{}, b.mapErr(err, false)
	}
	return entryOf(p, path.Base(p), a), nil
}

// Walk implements files.Backend: parents before children, server order,
// links reported and not entered.
func (b *Backend) Walk(ctx context.Context, p string, bud files.Budget, fn func(files.Entry) error) error {
	if b.r.cause() != nil {
		return fault.New(fault.SourceUnavailable, "")
	}
	root, err := b.rootEntry(ctx, p)
	if err != nil {
		return err
	}
	t := b.newTree(bud)
	var walk func(e files.Entry, depth int) error
	walk = func(e files.Entry, depth int) error {
		if err := ctx.Err(); err != nil {
			return b.mapErr(err, false)
		}
		if err := t.visit(e, depth); err != nil {
			return err
		}
		if err := fn(e); err != nil {
			return err
		}
		if !e.IsDir || e.IsSymlink {
			return nil
		}
		kids, err := b.readAll(ctx, e.Path, t.meta)
		if err != nil {
			return err
		}
		for _, k := range kids {
			if err := walk(k, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	return walk(root, 0)
}

// Remove implements files.Backend. A link is removed itself; a recursive
// delete removes children first, never follows links and stops at the
// budget without restoring what it deleted.
func (b *Backend) Remove(ctx context.Context, p string, recursive bool, bud files.Budget) error {
	if b.r.cause() != nil {
		return fault.New(fault.SourceUnavailable, "")
	}
	if p == "/" {
		return fault.New(fault.FilePermissionDenied, "")
	}
	root, err := b.rootEntry(ctx, p)
	if err != nil {
		return err
	}
	if !root.IsDir || root.IsSymlink {
		return b.removeOne(ctx, root)
	}
	if !recursive {
		err := b.removeOne(ctx, root)
		if fault.Is(err, fault.OperationFailed) && b.hasChildren(ctx, p) {
			return fault.New(fault.FileConflict, "")
		}
		return err
	}
	t := b.newTree(bud)
	if err := t.visit(root, 0); err != nil {
		return err
	}
	return b.removeTree(ctx, t, root, 0)
}

func (b *Backend) removeTree(ctx context.Context, t *tree, dir files.Entry, depth int) error {
	kids, err := b.readAll(ctx, dir.Path, t.meta)
	if err != nil {
		return err
	}
	for _, k := range kids {
		if err := ctx.Err(); err != nil {
			return b.mapErr(err, false)
		}
		if err := t.visit(k, depth+1); err != nil {
			return err
		}
		if k.IsDir && !k.IsSymlink {
			if err := b.removeTree(ctx, t, k, depth+1); err != nil {
				return err
			}
			continue
		}
		if err := b.removeOne(ctx, k); err != nil {
			return err
		}
	}
	return b.removeOne(ctx, dir)
}

// removeOne deletes one object: RMDIR for a directory, REMOVE otherwise.
func (b *Backend) removeOne(ctx context.Context, e files.Entry) error {
	rctx, cancel := b.request(ctx, true)
	defer cancel()
	var err error
	if e.IsDir && !e.IsSymlink {
		err = b.w.rmdir(rctx, e.Path)
	} else {
		err = b.w.remove(rctx, e.Path)
	}
	return b.mapErr(err, true)
}

func (b *Backend) hasChildren(ctx context.Context, p string) bool {
	d, err := b.openDir(ctx, p, &metaBudget{maxMembers: b.o.maxMembers(), maxBytes: b.o.MaxMetadataBytes}, false)
	if err != nil {
		return false
	}
	defer d.close()
	batch, err := d.take(ctx, 1)
	return err == nil && len(batch) > 0
}
