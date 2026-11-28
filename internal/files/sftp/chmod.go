package sftp

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"time"

	pkgsftp "github.com/pkg/sftp"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/files"
)

// Chmod implements files.Backend. It needs lsetstat@openssh.com, so the
// mode of a link target never changes: the object at path is checked with
// lstat before (no link, no set-id or sticky bits) and after the change.
func (b *Backend) Chmod(ctx context.Context, p string, perm fs.FileMode) error {
	return b.chmod(ctx, p, perm, nil)
}

// ChmodExpect is Chmod for an object the caller inspected: it changes
// nothing unless the object at p still has the type, permission bits,
// size, modification time and owner of want (METADATA_CHANGED).
//
// The server resolves links in the directories of p, so a directory
// replaced by a link between the caller's check and the request would
// redirect a change by path. A regular file is therefore changed through
// a handle (OPEN, FSTAT against want, FSETSTAT), which changes exactly
// the inspected file. A directory, and a file the account may not open,
// is changed with lsetstat right after the lstat that matched want; that
// one round trip remains (SFTP v3 has no *at() requests).
func (b *Backend) ChmodExpect(ctx context.Context, p string, perm fs.FileMode, want files.Entry) error {
	return b.chmod(ctx, p, perm, &want)
}

func (b *Backend) chmod(ctx context.Context, p string, perm fs.FileMode, want *files.Entry) error {
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
	if want != nil && !sameObject(before, *want) {
		return fault.New(fault.MetadataChanged, "")
	}
	target := uint32(perm.Perm())
	if before.mode&0o777 == target {
		return nil
	}
	if isRegular(before.mode) {
		done, err := b.chmodHandle(ctx, p, before, target)
		if done || err != nil {
			return err
		}
	}
	if err := b.w.lsetstat(ctx, p, target); err != nil {
		return b.mapErr(err, true)
	}
	after, err := b.w.lstat(ctx, p)
	if err != nil {
		return fault.Wrap(fault.OutcomeUnknown, err, "")
	}
	if after.mode&0o7777 != target || after.mode&modeType != before.mode&modeType {
		return fault.New(fault.ModeMismatch, "")
	}
	return nil
}

// chmodHandle changes a regular file on a handle whose FSTAT matches the
// lstat seen before. done is false when the account may not open the
// file or the server refuses OPEN; the caller then falls back to lsetstat.
func (b *Backend) chmodHandle(ctx context.Context, p string, before attrs, target uint32) (done bool, err error) {
	f, err := b.openFile(ctx, p, os.O_RDONLY)
	if err != nil {
		se, ok := errors.AsType[*pkgsftp.StatusError](err)
		if ok && (se.Code == fxPermissionDenied || se.Code == fxOpUnsupported) || errors.Is(err, fs.ErrPermission) {
			return false, nil
		}
		return true, b.mapErr(err, false)
	}
	defer closeFile(f)
	st, err := b.fstat(ctx, f)
	if err != nil {
		return true, b.mapErr(err, false)
	}
	want, _ := snapshotOf(before)
	if got, ok := snapshotOfStat(st); !ok || got != want {
		return true, fault.New(fault.MetadataChanged, "")
	}
	if _, err := await(ctx, func() (struct{}, error) { return struct{}{}, f.Chmod(os.FileMode(target)) }, nil); err != nil {
		return true, b.mapErr(err, true)
	}
	if st, err = b.fstat(ctx, f); err != nil {
		return true, fault.Wrap(fault.OutcomeUnknown, err, "")
	}
	if st.Mode&0o7777 != target || st.Mode&modeType != modeRegular {
		return true, fault.New(fault.ModeMismatch, "")
	}
	return true, nil
}

// sameObject reports whether a still describes what want described.
func sameObject(a attrs, want files.Entry) bool {
	if a.mode != want.Mode || int64(min(a.size, 1<<63-1)) != want.Size {
		return false
	}
	if a.has(attrACModTime) != !want.ModTime.IsZero() ||
		a.has(attrACModTime) && !time.Unix(int64(a.mtime), 0).Equal(want.ModTime) {
		return false
	}
	if a.has(attrUIDGID) != (want.Owner != nil) {
		return false
	}
	return want.Owner == nil || a.uid == want.Owner.UID && a.gid == want.Owner.GID
}
