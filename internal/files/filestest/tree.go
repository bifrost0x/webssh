package filestest

import (
	"context"
	"io/fs"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/files"
)

// Remove implements files.Backend.
func (b *Backend) Remove(ctx context.Context, p string, recursive bool, bud files.Budget) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.begin(ctx, "remove", p); err != nil {
		return err
	}
	n, ok := b.nodes[p]
	if !ok {
		return notFound()
	}
	if p == "/" && !b.caps.RootWritable {
		return fault.New(fault.FilePermissionDenied, "")
	}
	kids := b.children(p)
	if n.dir && len(kids) > 0 && !recursive {
		return fault.New(fault.FileConflict, "")
	}
	var tree []string
	if err := b.walk(p, bud.WithDefaults(), func(e files.Entry) error { tree = append(tree, e.Path); return nil }); err != nil {
		return err
	}
	for _, q := range tree {
		delete(b.nodes, q)
	}
	return nil
}

// Walk implements files.Backend.
func (b *Backend) Walk(ctx context.Context, p string, bud files.Budget, fn func(files.Entry) error) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.begin(ctx, "walk", p); err != nil {
		return err
	}
	if _, ok := b.nodes[p]; !ok {
		return notFound()
	}
	return b.walk(p, bud.WithDefaults(), fn)
}

func (b *Backend) walk(root string, bud files.Budget, fn func(files.Entry) error) error {
	members, bytesSeen := 0, int64(0)
	var visit func(p string, depth int) error
	visit = func(p string, depth int) error {
		n := b.nodes[p]
		members++
		bytesSeen += int64(len(n.data))
		switch {
		case members > bud.MaxMembers, bud.MaxBytes > 0 && bytesSeen > bud.MaxBytes:
			return fault.New(fault.LimitExceeded, "")
		case depth > bud.MaxDepth:
			return fault.New(fault.LimitExceeded, "")
		}
		if err := fn(b.entry(p, n)); err != nil {
			return err
		}
		if !n.dir {
			return nil
		}
		for _, c := range b.children(p) {
			if err := visit(c, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	return visit(root, 0)
}

// Chmod implements files.Backend.
func (b *Backend) Chmod(ctx context.Context, p string, perm fs.FileMode) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.begin(ctx, "chmod", p); err != nil {
		return err
	}
	if !b.caps.Ops.Has(files.CapChmod) {
		return fault.New(fault.UnsupportedOperation, "")
	}
	n, ok := b.nodes[p]
	if !ok {
		return notFound()
	}
	n.mode = n.mode&^0o777 | uint32(perm.Perm())
	return nil
}

// Close implements files.Backend.
func (b *Backend) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
	return nil
}

var _ files.Backend = (*Backend)(nil)
