package smb

import (
	"context"
	"errors"
	"io"
	"slices"
	"strings"

	smb2 "github.com/hirochachacha/go-smb2/v2"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/files"
)

var errLimit = fault.New(fault.LimitExceeded, "")

// node is one object found by a tree walk with its identity chain.
type node struct {
	files.Entry
	parts []string
	chain []uint64
}

// budget counts a tree walk against a files.Budget.
type budget struct {
	files.Budget
	members int
	bytes   int64
}

func (c *budget) add(e files.Entry, depth int) error {
	c.members++
	if !e.IsDir {
		c.bytes += e.Size
	}
	if c.members > c.MaxMembers || depth > c.MaxDepth || c.MaxBytes > 0 && c.bytes > c.MaxBytes {
		return errLimit
	}
	return nil
}

// walkTree visits the object at parts and everything below it, parents
// before children. Directories stay open, without FILE_SHARE_DELETE, while
// their children are read, so no directory of the walk can be renamed or
// replaced under it; every child directory is opened by name and must be
// the object its parent listed (FileId). Reparse points are visited and
// never entered. With expect the start must still have that identity
// chain; a changed tree is SOURCE_CHANGED.
func (b *Backend) walkTree(ctx context.Context, parts []string, expect []uint64, bud files.Budget, visit func(node) error) error {
	o, err := b.leaf(ctx, parts, expect, accessList, fileOpen, shareNoDelete, kindAny)
	if err != nil {
		return changed(err, expect != nil)
	}
	defer o.release()
	start := node{Entry: entry(o.info, joinPath(parts)), parts: parts, chain: o.chain}
	if len(parts) > 0 {
		start.Name = parts[len(parts)-1]
	}
	c := &budget{Budget: bud.WithDefaults()}
	if err := c.add(start.Entry, 0); err != nil {
		return err
	}
	if err := visit(start); err != nil {
		return err
	}
	if !start.IsDir {
		return nil
	}
	return b.walkDir(ctx, o.handle, start, 1, c, visit)
}

func (b *Backend) walkDir(ctx context.Context, dir *handle, at node, depth int, c *budget, visit func(node) error) error {
	for {
		if err := ctx.Err(); err != nil {
			return classifyCtx(ctx, err, PhaseFileOperation)
		}
		opCtx, cancel := b.op(ctx)
		infos, err := dir.file.Readdir(opCtx, pageDefault)
		if err != nil && !errors.Is(err, io.EOF) {
			err = b.fileError(opCtx, err)
			cancel()
			return changed(err, true)
		}
		cancel()
		for _, info := range infos {
			st, ok := info.Sys().(*smb2.FileStat)
			if !ok {
				return opFailed("MalformedEntry")
			}
			if st.FileName == "." || st.FileName == ".." {
				continue
			}
			n, err := b.childNode(at, st)
			if err != nil {
				return err
			}
			if err := c.add(n.Entry, depth); err != nil {
				return err
			}
			if err := visit(n); err != nil {
				return err
			}
			if n.IsDir {
				if err := b.descend(ctx, n, st.FileId, depth, c, visit); err != nil {
					return err
				}
			}
		}
		if err != nil || len(infos) == 0 {
			return nil
		}
	}
}

func (b *Backend) childNode(at node, st *smb2.FileStat) (node, error) {
	if !validID(st.FileId) {
		return node{}, fail(fault.SMBIdentityUnavailable, PhaseFileOperation, "IdentityError", nil)
	}
	parts, err := child(at.parts, st.FileName)
	if err != nil || st.EndOfFile < 0 {
		return node{}, opFailed("UnsafeName")
	}
	o := object{Name: st.FileName, ID: st.FileId, Attributes: st.FileAttributes, Size: st.EndOfFile, ModTime: st.LastWriteTime}
	return node{Entry: entry(o, joinPath(parts)), parts: parts, chain: append(slices.Clone(at.chain), st.FileId)}, nil
}

func (b *Backend) descend(ctx context.Context, n node, id uint64, depth int, c *budget, visit func(node) error) error {
	h, err := b.open(ctx, n.parts, accessList, fileOpen, 0, shareNoDelete, kindDir)
	if err != nil {
		return changed(err, true)
	}
	defer h.close()
	if h.info.ID != id || !h.matches(n.parts) {
		return fault.New(fault.SourceChanged, "")
	}
	return b.walkDir(ctx, h, n, depth+1, c, visit)
}

// changed reports a vanished or replaced object of an enumerated tree as
// SOURCE_CHANGED (FileSourceChanged of the Python release).
func changed(err error, enumerated bool) error {
	if !enumerated {
		return err
	}
	switch fault.CodeOf(err) {
	case fault.FileConflict, fault.SMBIdentityUnavailable, fault.FileNotFound, fault.SMBReparsePointRejected:
		return fault.Wrap(fault.SourceChanged, err, "")
	}
	return err
}

// Walk visits p and everything below it, parents before children, without
// entering reparse points, within b.
func (b *Backend) Walk(ctx context.Context, p string, bud files.Budget, fn func(files.Entry) error) error {
	if err := b.alive(); err != nil {
		return err
	}
	parts, err := b.parts(p)
	if err != nil {
		return err
	}
	return b.walkTree(ctx, parts, nil, bud, func(n node) error { return fn(n.Entry) })
}

// Remove deletes the object at p. A directory with recursive is deleted
// children first within bud; a tree that holds a reparse point is refused
// before anything is deleted (Python rule). Every deletion checks the
// identity chain the walk found, so an object replaced in the meantime is
// not deleted (SOURCE_CHANGED); nothing is restored after a partial
// delete.
func (b *Backend) Remove(ctx context.Context, p string, recursive bool, bud files.Budget) error {
	parts, err := b.mutable(p)
	if err != nil {
		return err
	}
	if err := b.alive(); err != nil {
		return err
	}
	o, err := b.leaf(ctx, parts, nil, accessAttributes, fileOpen, shareAll, kindAny)
	if err != nil {
		return err
	}
	start, isDir := o.chain, o.info.isDir()
	o.release()
	if !isDir || !recursive {
		return b.deleteOne(ctx, parts, start)
	}
	var nodes []node
	err = b.walkTree(ctx, parts, start, bud, func(n node) error {
		if n.IsSymlink {
			return fail(fault.SMBReparsePointRejected, PhaseFileOperation, "ReparsePoint", nil)
		}
		nodes = append(nodes, n)
		return nil
	})
	if err != nil {
		return err
	}
	// Files first, then directories, deepest first; the start comes last.
	slices.SortStableFunc(nodes, func(x, y node) int {
		if x.IsDir != y.IsDir {
			if x.IsDir {
				return 1
			}
			return -1
		}
		return strings.Count(y.Path, "/") - strings.Count(x.Path, "/")
	})
	for _, n := range nodes {
		if err := ctx.Err(); err != nil {
			return classifyCtx(ctx, err, PhaseFileOperation)
		}
		if err := b.deleteOne(ctx, n.parts, n.chain); err != nil {
			return changed(err, true)
		}
	}
	return nil
}

// deleteOne sets the delete disposition on a verified handle. A read-only
// file is retried once with the attribute cleared; when that fails, the
// attributes are restored (_verified_delete).
func (b *Backend) deleteOne(ctx context.Context, parts []string, chain []uint64) error {
	return b.mutate(ctx, func(ctx context.Context, s *step) error {
		o, err := b.leaf(ctx, parts, chain, accessDelete, fileOpen, shareAll, kindAny)
		if err != nil {
			return err
		}
		defer o.release()
		s.send()
		err = o.markDelete(ctx)
		d, ok := errors.AsType[*diagnostic](err)
		if err == nil || !ok || d.status != statusCannotDelete || o.info.Attributes&attrReadOnly == 0 {
			return err
		}
		ro, err := b.leaf(ctx, parts, chain, accessDeleteReadOnly, fileOpen, shareAll, kindAny)
		if err != nil {
			return err
		}
		defer ro.release()
		original := ro.info.Attributes
		if original&attrReadOnly == 0 {
			return fault.New(fault.FileConflict, "")
		}
		writable := original &^ attrReadOnly
		if writable == 0 {
			writable = attrNormal
		}
		if err := ro.setAttributes(ctx, writable); err != nil {
			return err
		}
		if err := ro.markDelete(ctx); err != nil {
			restore, cancel := context.WithTimeout(context.WithoutCancel(ctx), b.ioIdle)
			defer cancel()
			return errors.Join(err, ro.setAttributes(restore, original))
		}
		return nil
	})
}
