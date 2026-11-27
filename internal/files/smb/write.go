package smb

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"hash"
	"io"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/files"
)

// maxEditorBytes is MAX_EDITOR_FILE_SIZE: the largest file whose revision
// the backend hashes for an editor save.
const maxEditorBytes = 5 << 20

// tempLeaf names a generated sibling of name: ".<name>.webssh-<purpose>-
// <24 hex>" plus suffix, as in the Python release, so that leftovers are
// recognisable.
func tempLeaf(name, purpose, suffix string) (string, error) {
	var token [12]byte
	if _, err := rand.Read(token[:]); err != nil {
		return "", err
	}
	return "." + name + ".webssh-" + purpose + "-" + hex.EncodeToString(token[:]) + suffix, nil
}

// sibling is parts with the leaf replaced by leaf.
func sibling(parts []string, leaf string) ([]string, error) {
	return child(parts[:len(parts)-1], leaf)
}

// Write stores src at p as one replacement: the bytes go to an exclusive
// temporary file beside p, which is then renamed over p through its own
// handle (ReplaceIfExists unless o.Exclusive). Readers see the old or the
// new content and p is never truncated or written in place, so no failure
// loses data: a failure before the rename leaves p as it was and deletes
// the temporary file through its handle; a lost reply to the rename is
// reconciled through that handle, and when it cannot be settled the
// temporary file is kept and the result is OUTCOME_UNKNOWN.
//
// An editor save (o.ExpectedRevision) with StrategyAtomic is answered
// with SMB_RECOVERABLE_REPLACE_REQUIRED and the current revision, as in
// the Python release: the page asks the user to confirm the recoverable
// swap (StrategyRecoverableSwap), which checks the revision on the very
// handle it renames.
func (b *Backend) Write(ctx context.Context, p string, src io.Reader, o files.WriteOptions) (files.WriteResult, error) {
	if err := b.alive(); err != nil {
		return files.WriteResult{}, err
	}
	parts, err := b.mutable(p)
	if err != nil {
		return files.WriteResult{}, err
	}
	if o.FollowSymlink {
		return files.WriteResult{}, fail(fault.SMBReparsePointRejected, PhaseFileOperation, "ReparsePoint", nil)
	}
	switch o.Strategy {
	case "", files.StrategyAtomic:
		if o.ExpectedRevision != "" {
			return files.WriteResult{}, b.swapRequired(ctx, parts, o.ExpectedRevision)
		}
		return b.atomicWrite(ctx, parts, src, o)
	case files.StrategyRecoverableSwap:
		if o.ExpectedRevision == "" || o.Exclusive {
			return files.WriteResult{}, fault.New(fault.InvalidRequest, "A recoverable replace needs the revision of an existing file.")
		}
		return b.swap(ctx, parts, src, o)
	}
	return files.WriteResult{}, fault.New(fault.InvalidRequest, "Invalid replacement strategy.")
}

// swapRequired hashes the current file: a stale revision is EDIT_CONFLICT,
// otherwise the save needs the user's consent to a recoverable swap.
func (b *Backend) swapRequired(ctx context.Context, parts []string, expected string) error {
	o, err := b.leaf(ctx, parts, nil, accessRead, fileOpen, shareAll, kindFile)
	if err != nil {
		return err
	}
	defer o.release()
	current, err := b.revision(ctx, o.handle)
	if err != nil {
		return err
	}
	if current != expected {
		return fault.New(fault.EditConflict, "The file changed on the server. Reopen it before saving.")
	}
	e := fault.New(fault.SMBRecoverableReplaceNeed, "A recoverable SMB replacement must be confirmed before saving this file.")
	e.Details = map[string]any{"revision": current}
	return e
}

// revision is the SHA-256 of the whole file read through h.
func (b *Backend) revision(ctx context.Context, h *handle) (string, error) {
	if h.info.Size > maxEditorBytes {
		return "", fault.New(fault.FileTooLarge, "File too large to edit")
	}
	if _, err := h.file.Seek(ctx, 0, io.SeekStart); err != nil {
		return "", b.fileError(ctx, err)
	}
	sum := sha256.New()
	buf := make([]byte, chunk)
	var total int64
	for {
		opCtx, cancel := b.op(ctx)
		n, err := h.file.Read(opCtx, buf)
		cancel()
		sum.Write(buf[:n])
		total += int64(n)
		if total > maxEditorBytes {
			return "", fault.New(fault.FileTooLarge, "File too large to edit")
		}
		if errors.Is(err, io.EOF) || err == nil && n == 0 {
			return hex.EncodeToString(sum.Sum(nil)), nil
		}
		if err != nil {
			return "", b.fileError(opCtx, err)
		}
	}
}

func (b *Backend) atomicWrite(ctx context.Context, parts []string, src io.Reader, o files.WriteOptions) (files.WriteResult, error) {
	release, _, err := b.ancestors(ctx, parts, nil)
	if err != nil {
		return files.WriteResult{}, err
	}
	defer release()
	if err := b.checkDestination(ctx, parts, o.Exclusive); err != nil {
		return files.WriteResult{}, err
	}
	leaf, err := tempLeaf(parts[len(parts)-1], "write", ".tmp")
	if err != nil {
		return files.WriteResult{}, opFailed("Random")
	}
	tmp, err := sibling(parts, leaf)
	if err != nil {
		return files.WriteResult{}, fault.Wrap(fault.InvalidRequest, err, "The path is invalid.")
	}
	h, err := b.open(ctx, tmp, accessCreateMove, fileCreate, 0, 0, kindFile)
	if err != nil {
		return files.WriteResult{}, err
	}
	keep := false
	defer func() {
		if !keep {
			b.discard(h)
		}
		_ = h.close()
	}()
	res, err := b.copyIn(ctx, h, src, o)
	if err != nil {
		return files.WriteResult{}, err
	}
	if err := ctx.Err(); err != nil {
		return files.WriteResult{}, classifyCtx(ctx, err, PhaseFileOperation)
	}
	if err := b.checkDestination(ctx, parts, o.Exclusive); err != nil {
		return files.WriteResult{}, err
	}
	err = b.install(ctx, h, tmp, parts, !o.Exclusive)
	switch {
	case err == nil:
		keep = true
		return res, nil
	case isCode(err, fault.OutcomeUnknown):
		keep = true
		fe, _ := fault.From(err)
		fe.Details = map[string]any{"recovery_leaves": []string{leaf}}
		return files.WriteResult{}, fe
	case o.Exclusive:
		return files.WriteResult{}, err
	case isCode(err, fault.FilePermissionDenied), isCode(err, fault.FileConflict):
		return files.WriteResult{}, fault.Wrap(fault.AtomicReplaceUnavailable, err, "")
	}
	return files.WriteResult{}, err
}

// checkDestination refuses a destination that is a directory or a
// reparse point, and with exclusive any existing one.
func (b *Backend) checkDestination(ctx context.Context, parts []string, exclusive bool) error {
	h, err := b.open(ctx, parts, accessAttributes, fileOpen, 0, shareAll, kindAny)
	if isCode(err, fault.FileNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	defer h.close()
	if exclusive || h.info.isDir() {
		return fault.New(fault.FileConflict, "")
	}
	return nil
}

// install renames the handle of tmp to dest under the mutation deadline
// and reconciles a lost reply through the handle.
func (b *Backend) install(ctx context.Context, h *handle, tmp, dest []string, replace bool) error {
	mctx, cancel := context.WithTimeout(ctx, b.mutation)
	defer cancel()
	err := h.rename(mctx, dest, replace)
	if err == nil {
		return nil
	}
	err = b.reconcile(err, func() (bool, bool) {
		switch h.location(dest, tmp) {
		case 0:
			return true, true
		case 1:
			return false, true
		}
		return false, false
	})
	if isCode(err, fault.FileTimeout) {
		// Not carried out, but the request is gone without an answer: the
		// temporary file stays for the same reason as an unknown outcome.
		return fail(fault.OutcomeUnknown, PhaseFileOperation, "OutcomeUnknown", err)
	}
	return err
}

// discard deletes a generated file through its own handle, also after the
// caller's context ended; false leaves it in place.
func (b *Backend) discard(h *handle) bool {
	if b.dead.Load() {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), b.ioIdle)
	defer cancel()
	return h.markDelete(ctx) == nil
}

// copyIn writes src to h in chunks, each bounded by the I/O idle timeout,
// and checks the declared size and the byte limit.
func (b *Backend) copyIn(ctx context.Context, h *handle, src io.Reader, o files.WriteOptions) (files.WriteResult, error) {
	sum := sha256.New()
	buf := make([]byte, chunk)
	var total int64
	for {
		n, rerr := io.ReadFull(src, buf)
		if n > 0 {
			total += int64(n)
			if o.MaxBytes > 0 && total > o.MaxBytes {
				return files.WriteResult{}, fault.New(fault.LimitExceeded, "")
			}
			if o.Size >= 0 && total > o.Size {
				return files.WriteResult{}, fault.New(fault.SourceChanged, "")
			}
			if err := b.writeChunk(ctx, h, buf[:n], sum); err != nil {
				return files.WriteResult{}, err
			}
		}
		if errors.Is(rerr, io.EOF) || errors.Is(rerr, io.ErrUnexpectedEOF) {
			break
		}
		if rerr != nil {
			if fe, ok := fault.From(rerr); ok {
				return files.WriteResult{}, fe
			}
			return files.WriteResult{}, fault.Wrap(fault.SourceChanged, rerr, "")
		}
	}
	if o.Size >= 0 && total != o.Size {
		return files.WriteResult{}, fault.New(fault.SourceChanged, "")
	}
	return files.WriteResult{Revision: hex.EncodeToString(sum.Sum(nil)), Size: total}, nil
}

func (b *Backend) writeChunk(ctx context.Context, h *handle, p []byte, sum hash.Hash) error {
	if err := b.alive(); err != nil {
		return err
	}
	opCtx, cancel := b.op(ctx)
	defer cancel()
	n, err := h.file.Write(opCtx, p)
	if err != nil {
		return b.fileError(opCtx, err)
	}
	if n != len(p) {
		return opFailed("ShortWrite")
	}
	sum.Write(p)
	return nil
}
