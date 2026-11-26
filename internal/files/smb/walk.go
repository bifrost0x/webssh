package smb

import (
	"context"
	"slices"

	"github.com/bifrost0x/webssh/internal/fault"
)

// ancestors opens the share root and every directory above the leaf of
// parts without following a reparse point and holds them without
// FILE_SHARE_DELETE, so that no ancestor can be renamed, replaced or
// deleted until release runs. Each held handle must be a directory bound
// to the requested name; a non-directory is NOT_FOUND and a different
// binding CONFLICT. With expect (the identity chain of an earlier walk,
// one FileId per component of parts) every ancestor must still be the
// same object; otherwise CONFLICT.
//
// Opening every prefix by its full name, rather than querying it in the
// listing of its parent, also covers servers that deny listing a parent
// but allow traversing it (the list-denied fallback of the Python
// release): the held handles bind the names, so the second verification
// pass Python needed is not.
//
// ids are the FileIds of the held ancestors below the root.
func (b *Backend) ancestors(ctx context.Context, parts []string, expect []uint64) (release func(), ids []uint64, err error) {
	if expect != nil && len(expect) != len(parts) {
		return nil, nil, fail(fault.SMBIdentityUnavailable, PhaseFileOperation, "IdentityChain", nil)
	}
	held := make([]*handle, 0, len(parts))
	release = func() {
		for _, h := range slices.Backward(held) {
			_ = h.close()
		}
	}
	for i := range len(parts) {
		// Untyped, so that a reparse point is reported as such before the
		// directory check, as Python does.
		h, err := b.open(ctx, parts[:i], accessAttributes, fileOpen, 0, shareNoDelete, kindAny)
		if err != nil {
			release()
			return nil, nil, err
		}
		held = append(held, h)
		switch {
		case !h.info.isDir():
			err = fail(fault.FileNotFound, PhaseFileOperation, "NotADirectory", nil)
		case i > 0 && !h.matches(parts[:i]):
			err = fail(fault.FileConflict, PhaseFileOperation, "NameBinding", nil)
		case i > 0 && expect != nil && expect[i-1] != h.info.ID:
			err = fail(fault.FileConflict, PhaseFileOperation, "IdentityChanged", nil)
		}
		if err != nil {
			release()
			return nil, nil, err
		}
		if i > 0 {
			ids = append(ids, h.info.ID)
		}
	}
	return release, ids, nil
}

// opened is a leaf handle below held ancestors.
type opened struct {
	*handle
	release func() // closes the handle, then releases the ancestors
	chain   []uint64
}

// leaf opens the object at parts below held ancestors and checks its
// binding and, with expect, its identity. chain is the identity chain of
// the object: the FileIds of its ancestors below the root and its own.
func (b *Backend) leaf(ctx context.Context, parts []string, expect []uint64, access, disposition, share uint32, kind openKind) (opened, error) {
	release, ids, err := b.ancestors(ctx, parts, expect)
	if err != nil {
		return opened{}, err
	}
	h, err := b.open(ctx, parts, access, disposition, 0, share, kind)
	if err != nil {
		release()
		return opened{}, err
	}
	if len(parts) > 0 && disposition == fileOpen && (!h.matches(parts) || expect != nil && expect[len(parts)-1] != h.info.ID) {
		_ = h.close()
		release()
		return opened{}, fail(fault.FileConflict, PhaseFileOperation, "IdentityChanged", nil)
	}
	o := opened{handle: h, release: func() { _ = h.close(); release() }}
	if len(parts) > 0 {
		o.chain = append(ids, h.info.ID)
	}
	return o, nil
}
