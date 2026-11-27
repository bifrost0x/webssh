package sftp

import (
	"context"
	"encoding/hex"
	"io"
	"os"
	"slices"

	pkgsftp "github.com/pkg/sftp"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/files"
)

// maxEditorBytes is MAX_EDITOR_FILE_SIZE, the bound of the revision check
// when the caller gives no MaxBytes.
const maxEditorBytes = 5 << 20

// writeJob is one Write: the rules of atomic_transfer_writer (transfers,
// new files) and write_file_text (editor saves, ExpectedRevision) of the
// Python release on one path.
type writeJob struct {
	b        *Backend
	o        files.WriteOptions
	editor   bool
	src      io.Reader
	target   string
	exists   bool
	original snapshot
	revision string // editor: the revision seen before staging
	tmp      string
	created  bool
	publish  bool
}

// fails returns the code of a rule that differs between editor and
// transfer.
func (j *writeJob) fails(editor, transfer fault.Code, message string) error {
	if j.editor {
		return fault.New(editor, message)
	}
	return fault.New(transfer, "")
}

// Write implements files.Backend. The content goes into a hidden staging
// file beside the target (created exclusively), then replaces the target
// with posix-rename@openssh.com, or takes a new name with a rename that
// never replaces. A replacement keeps the permission bits and owner of
// the file it replaces; when that is impossible nothing is replaced. A
// lost reply after the final rename was sent is OUTCOME_UNKNOWN
// (SAVE_OUTCOME_UNKNOWN for an editor save) and the staging file stays.
func (b *Backend) Write(ctx context.Context, p string, src io.Reader, o files.WriteOptions) (files.WriteResult, error) {
	if o.Strategy != "" && o.Strategy != files.StrategyAtomic {
		return files.WriteResult{}, fault.New(fault.AtomicReplaceUnavailable, "")
	}
	if b.r.cause() != nil {
		return files.WriteResult{}, fault.New(fault.SourceUnavailable, "")
	}
	if err := ctx.Err(); err != nil {
		return files.WriteResult{}, b.mapErr(err, false)
	}
	j := &writeJob{b: b, o: o, editor: o.ExpectedRevision != "", src: src, target: p}
	res, err := j.run(ctx)
	if j.created && !j.publish {
		// The staging file was never published: remove it. An uncertain
		// rename keeps it, because which object owns which name is unknown.
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), b.o.MutationTimeout)
		_ = b.w.remove(rctx, j.tmp)
		cancel()
	}
	return res, err
}

func (j *writeJob) run(ctx context.Context) (files.WriteResult, error) {
	b := j.b
	if err := j.inspect(ctx); err != nil {
		return files.WriteResult{}, err
	}
	purpose := "write"
	if j.editor {
		purpose = "tmp"
	}
	j.tmp = stagingPath(j.target, purpose)
	rctx, cancel := b.request(ctx, true)
	f, err := b.openFile(rctx, j.tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL)
	cancel()
	if err != nil {
		return files.WriteResult{}, b.mapErr(err, false)
	}
	j.created = true
	closed := false
	defer func() {
		if !closed {
			closeFile(f)
		}
	}()
	if err := j.stage(ctx, f); err != nil {
		return files.WriteResult{}, err
	}
	s := newSource(ctx, j.src, j.o)
	_, werr := f.ReadFrom(s)
	if err := s.fault(); err != nil {
		return files.WriteResult{}, err
	}
	if werr != nil {
		return files.WriteResult{}, b.mapErr(werr, false)
	}
	if j.exists {
		if err := j.keepMetadata(ctx, f); err != nil {
			return files.WriteResult{}, err
		}
	}
	// A confirmed CLOSE: the server has every byte.
	closed = true
	cctx, cancel := b.request(ctx, true)
	_, err = await(cctx, func() (struct{}, error) { return struct{}{}, f.Close() }, nil)
	cancel()
	if err != nil {
		return files.WriteResult{}, b.mapErr(err, false)
	}
	if err := j.publishTmp(ctx); err != nil {
		return files.WriteResult{}, err
	}
	return files.WriteResult{Revision: hex.EncodeToString(s.h.Sum(nil)), Size: s.n}, nil
}

// inspect resolves a link (editor), reads what a replacement must keep and
// checks the editor's revision.
func (j *writeJob) inspect(ctx context.Context) error {
	b := j.b
	rctx, cancel := b.request(ctx, false)
	defer cancel()
	a, err := b.w.lstat(rctx, j.target)
	if isStatus(err, fxNoSuchFile) {
		if j.editor {
			return fault.New(fault.EditConflict, msgFileChanged)
		}
		return nil
	}
	if err != nil {
		return b.mapErr(err, false)
	}
	if isLink(a.mode) {
		if !j.o.FollowSymlink {
			return fault.New(fault.UnsupportedOperation, "")
		}
		// Saving replaces the link target, never the link; REALPATH
		// resolves the whole chain.
		resolved, err := b.w.resolve(rctx, j.target)
		if err != nil {
			return b.mapErr(err, false)
		}
		clean, cerr := files.CleanTarget(resolved)
		if cerr != nil || clean != resolved || clean == j.target {
			return fault.New(fault.OperationFailed, msgLinkUnresolved)
		}
		j.target = clean
		if a, err = b.w.lstat(rctx, j.target); err != nil {
			return b.mapErr(err, false)
		}
	}
	j.exists = true
	if j.o.Exclusive {
		return fault.New(fault.FileConflict, "")
	}
	snap, ok := snapshotOf(a)
	switch {
	case ok && snap.dir:
		return fault.New(fault.FileConflict, "")
	case !ok:
		return j.fails(fault.EditMetadataUnsupported, fault.AtomicReplaceUnavailable, msgSpecialBits)
	case snap.special != 0:
		return j.fails(fault.EditMetadataUnsupported, fault.AtomicReplaceUnavailable, msgSpecialBits)
	case !slices.Contains(b.caps.Replace, files.StrategyAtomic):
		return fault.New(fault.AtomicReplaceUnavailable, "")
	}
	j.original = snap
	if j.editor {
		rev, err := b.revisionOf(rctx, j.target, j.editorLimit())
		if err != nil {
			return err
		}
		if rev != j.o.ExpectedRevision {
			return fault.New(fault.EditConflict, msgFileChanged)
		}
		j.revision = rev
	}
	return nil
}

func (j *writeJob) editorLimit() int64 {
	if j.o.MaxBytes > 0 {
		return j.o.MaxBytes
	}
	return maxEditorBytes
}

// stage makes the new file private before any byte is written: a
// replacement is never more visible to group or others than the file it
// replaces, even on a server that forces a create mode.
func (j *writeJob) stage(ctx context.Context, f *pkgsftp.File) error {
	b := j.b
	rctx, cancel := b.request(ctx, true)
	defer cancel()
	if j.exists || j.editor {
		if _, err := await(rctx, func() (struct{}, error) { return struct{}{}, f.Chmod(0o600) }, nil); err != nil {
			return b.mapErr(err, false)
		}
	}
	st, err := b.fstat(rctx, f)
	if err != nil {
		return b.mapErr(err, false)
	}
	staged, ok := snapshotOfStat(st)
	if !ok || staged.dir || staged.special != 0 || staged.size != 0 {
		return fault.New(fault.OperationFailed, msgStagingUnsafe)
	}
	if j.exists && staged.perm&^j.original.perm&0o077 != 0 {
		return fault.New(fault.OperationFailed, msgStagingUnsafe)
	}
	return nil
}

// keepMetadata gives the staged file the owner and permission bits of the
// file it replaces and checks them on the handle (FSTAT).
func (j *writeJob) keepMetadata(ctx context.Context, f *pkgsftp.File) error {
	b := j.b
	rctx, cancel := b.request(ctx, true)
	defer cancel()
	if err := j.unchanged(rctx); err != nil {
		return err
	}
	st, err := b.fstat(rctx, f)
	if err != nil {
		return b.mapErr(err, false)
	}
	staged, _ := snapshotOfStat(st)
	orig := j.original
	if orig.owner && staged.uid != orig.uid {
		return j.fails(fault.EditMetadataUnsupported, fault.AtomicReplaceUnavailable, msgOwnerKept)
	}
	if orig.owner && staged.gid != orig.gid {
		if j.editor {
			return fault.New(fault.EditMetadataUnsupported, msgOwnerKept)
		}
		// Shared directories often give new files the user's primary
		// group; an owner who belongs to the original group may restore it.
		if _, err := await(rctx, func() (struct{}, error) {
			return struct{}{}, f.Chown(int(orig.uid), int(orig.gid))
		}, nil); err != nil {
			return fault.Wrap(fault.AtomicReplaceUnavailable, err, "")
		}
	}
	if _, err := await(rctx, func() (struct{}, error) { return struct{}{}, f.Chmod(os.FileMode(orig.perm)) }, nil); err != nil {
		return j.fails(fault.EditMetadataUnsupported, fault.AtomicReplaceUnavailable, msgOwnerKept)
	}
	if st, err = b.fstat(rctx, f); err != nil {
		return b.mapErr(err, false)
	}
	got, _ := snapshotOfStat(st)
	if got.perm != orig.perm || got.special != 0 || orig.owner && (got.uid != orig.uid || got.gid != orig.gid) {
		return j.fails(fault.EditMetadataUnsupported, fault.AtomicReplaceUnavailable, msgOwnerKept)
	}
	return nil
}

// unchanged checks that the target still has the state seen at the start.
func (j *writeJob) unchanged(ctx context.Context) error {
	a, err := j.b.w.lstat(ctx, j.target)
	cur, ok := snapshotOf(a)
	if err != nil || !ok || cur != j.original {
		return j.fails(fault.EditConflict, fault.FileConflict, msgFileChanged)
	}
	return nil
}

// publishTmp installs the staged file under the target name.
func (j *writeJob) publishTmp(ctx context.Context) error {
	b := j.b
	rctx, cancel := b.request(ctx, true)
	defer cancel()
	if !j.exists {
		if b.exists(rctx, j.target) {
			return fault.New(fault.FileConflict, "")
		}
		j.publish = true
		err := b.w.rename(rctx, j.tmp, j.target)
		if err != nil && answered(err) {
			j.publish = false
			if isStatus(err, fxFailure) && b.exists(rctx, j.target) {
				return fault.New(fault.FileConflict, "")
			}
		}
		return b.mapErr(err, true)
	}
	if err := j.unchanged(rctx); err != nil {
		return err
	}
	if j.editor {
		// Check the bytes again after staging: this detects edits seen
		// meanwhile, without claiming a server-side compare-and-swap.
		rev, err := b.revisionOf(rctx, j.target, j.editorLimit())
		if err != nil {
			return err
		}
		if rev != j.revision {
			return fault.New(fault.EditConflict, msgFileChanged)
		}
	}
	j.publish = true
	err := b.w.posixRename(rctx, j.tmp, j.target)
	if err == nil {
		return nil
	}
	if answered(err) {
		j.publish = false
		if isStatus(err, fxOpUnsupported) {
			return fault.New(fault.AtomicReplaceUnavailable, "")
		}
		return b.mapErr(err, false)
	}
	if j.editor {
		return fault.Wrap(fault.SaveOutcomeUnknown, err, msgSaveUncertain)
	}
	return fault.Wrap(fault.OutcomeUnknown, err, "")
}
