package smb

import (
	"context"
	"errors"
	"io"

	smb2 "github.com/hirochachacha/go-smb2/v2"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/files"
)

// Synthesised POSIX modes (_directory_payload of app/smb_backend.py).
const (
	modeDir     = 0o040000 | 0o111
	modeFile    = 0o100000
	modeRO      = 0o444
	modeRW      = 0o666
	pageDefault = 500
)

// entry converts metadata to the entry the page shows. A reparse point is
// listed as a link and never as a directory.
func entry(o object, p string) files.Entry {
	mode := uint32(modeFile)
	if o.isDir() {
		mode = modeDir
	}
	if o.Attributes&attrReadOnly != 0 {
		mode |= modeRO
	} else {
		mode |= modeRW
	}
	return files.Entry{Name: o.Name, Path: p, Size: o.Size, Mode: mode, IsDir: o.isDir() && !o.isReparse(),
		IsSymlink: o.isReparse(), ModTime: o.ModTime}
}

// Stat describes the object at p. Reparse points are never followed:
// with follow one is refused, so a path that names no link describes
// itself either way.
func (b *Backend) Stat(ctx context.Context, p string, follow bool) (files.Entry, error) {
	if err := b.alive(); err != nil {
		return files.Entry{}, err
	}
	parts, err := b.parts(p)
	if err != nil {
		return files.Entry{}, err
	}
	o, err := b.leaf(ctx, parts, nil, accessAttributes, fileOpen, shareAll, kindAny)
	if err != nil {
		return files.Entry{}, err
	}
	defer o.release()
	e := entry(o.info, joinPath(parts))
	if len(parts) == 0 {
		e.Name = ""
	} else {
		e.Name = parts[len(parts)-1]
	}
	if follow && e.IsSymlink {
		return files.Entry{}, fail(fault.SMBReparsePointRejected, PhaseFileOperation, "ReparsePoint", nil)
	}
	return e, nil
}

// listing is an open directory read below held ancestors.
type listing struct {
	b      *Backend
	o      opened
	dir    []string
	closed bool
}

// OpenListing opens the directory at p for reading.
func (b *Backend) OpenListing(ctx context.Context, p string) (files.Listing, error) {
	if err := b.alive(); err != nil {
		return nil, err
	}
	parts, err := b.parts(p)
	if err != nil {
		return nil, err
	}
	o, err := b.leaf(ctx, parts, nil, accessList, fileOpen, shareAll, kindDir)
	if err != nil {
		return nil, err
	}
	return &listing{b: b, o: o, dir: parts}, nil
}

// Next returns up to max entries in server order without "." and "..".
// A name the share path rules cannot address, or an entry without a
// usable identity, fails the listing as in the Python release.
func (l *listing) Next(ctx context.Context, max int) ([]files.Entry, bool, error) {
	if l.closed {
		return nil, false, errUnavailable
	}
	if err := l.b.alive(); err != nil {
		return nil, false, err
	}
	if max <= 0 {
		max = pageDefault
	}
	opCtx, cancel := l.b.op(ctx)
	defer cancel()
	infos, err := l.o.file.Readdir(opCtx, max)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, false, l.b.fileError(opCtx, err)
	}
	out := make([]files.Entry, 0, len(infos))
	for _, info := range infos {
		e, err := l.entry(info)
		if err != nil {
			return nil, false, err
		}
		if e.Name != "" {
			out = append(out, e)
		}
	}
	return out, err == nil && len(infos) > 0, nil
}

func (l *listing) entry(info interface{ Sys() any }) (files.Entry, error) {
	st, ok := info.Sys().(*smb2.FileStat)
	if !ok {
		return files.Entry{}, opFailed("MalformedEntry")
	}
	if st.FileName == "." || st.FileName == ".." {
		return files.Entry{}, nil
	}
	if !validID(st.FileId) {
		return files.Entry{}, fail(fault.SMBIdentityUnavailable, PhaseFileOperation, "IdentityError", nil)
	}
	if st.EndOfFile < 0 {
		return files.Entry{}, opFailed("MalformedEntry")
	}
	parts, err := child(l.dir, st.FileName)
	if err != nil {
		return files.Entry{}, opFailed("UnsafeName")
	}
	return entry(object{Name: st.FileName, ID: st.FileId, Attributes: st.FileAttributes, Size: st.EndOfFile,
		ModTime: st.LastWriteTime}, joinPath(parts)), nil
}

// Close releases the directory and its ancestors.
func (l *listing) Close() error {
	if !l.closed {
		l.closed = true
		l.o.release()
	}
	return nil
}

// Mkdir creates one directory; the parent must exist, an existing name is
// CONFLICT.
func (b *Backend) Mkdir(ctx context.Context, p string) error {
	parts, err := b.mutable(p)
	if err != nil {
		return err
	}
	return b.mutate(ctx, func(ctx context.Context, s *step) error {
		release, _, err := b.ancestors(ctx, parts, nil)
		if err != nil {
			return err
		}
		defer release()
		s.send()
		h, err := b.open(ctx, parts, accessAttributes, fileCreate, 0, shareAll, kindDir)
		if err != nil {
			return err
		}
		return h.close()
	})
}

// Rename moves from to to through a handle on the source object; it never
// replaces. A lost reply is reconciled through that handle.
func (b *Backend) Rename(ctx context.Context, from, to string) error {
	src, err := b.mutable(from)
	if err != nil {
		return err
	}
	dst, err := b.mutable(to)
	if err != nil {
		return err
	}
	return b.mutate(ctx, func(ctx context.Context, s *step) error {
		o, err := b.leaf(ctx, src, nil, accessDelete, fileOpen, shareAll, kindAny)
		if err != nil {
			return err
		}
		defer o.release()
		release, _, err := b.ancestors(ctx, dst, nil)
		if err != nil {
			return err
		}
		defer release()
		s.send()
		err = o.rename(ctx, dst, false)
		return b.reconcile(err, func() (bool, bool) {
			switch o.location(dst, src) {
			case 0:
				return true, true
			case 1:
				return false, true
			}
			return false, false
		})
	})
}
