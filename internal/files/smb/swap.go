package smb

import (
	"context"
	"io"
	"strings"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/files"
)

// Messages of the recoverable swap (app/smb_backend.py).
const (
	msgTempRemains      = "The save failed and a temporary recovery file remains."
	msgSaveUncertain    = "The save outcome is uncertain. Manual recovery may be required."
	msgReplaceUncertain = "The replacement outcome is uncertain. Manual recovery is required."
	msgRollbackFailed   = "The replacement and automatic rollback failed. Manual recovery is required."
	msgRestoredTemp     = "The original file was restored, but a temporary recovery file remains."
	msgRestored         = "The replacement failed. The original file was restored."
)

func recoveryRequired(message string, leaves ...string) error {
	e := fault.New(fault.SMBRecoveryRequired, message)
	e.Details = map[string]any{"recovery_leaves": leaves}
	return e
}

// swap installs an editor save after the user confirmed it, using only
// handles bound to their objects (_recoverable_replace_guarded): the
// target is opened without write or delete sharing and its revision is
// checked on that handle; the new bytes go to an exclusive temporary
// file; the target is renamed to a recovery name, the temporary file to
// the target name, and the recovery file is deleted. A step that fails is
// rolled back through the handles; whatever cannot be settled is reported
// with the names of the files that remain, never by deleting one.
func (b *Backend) swap(ctx context.Context, parts []string, src io.Reader, o files.WriteOptions) (files.WriteResult, error) {
	release, _, err := b.ancestors(ctx, parts, nil)
	if err != nil {
		return files.WriteResult{}, err
	}
	defer release()
	dest, err := b.open(ctx, parts, accessFileMove, fileOpen, 0, shareRead, kindFile)
	if err != nil {
		return files.WriteResult{}, err
	}
	defer dest.close()
	current, err := b.revision(ctx, dest)
	if err != nil {
		return files.WriteResult{}, err
	}
	if current != o.ExpectedRevision {
		return files.WriteResult{}, fault.New(fault.EditConflict, "The file changed on the server. Reopen it before saving.")
	}
	name := parts[len(parts)-1]
	tmpLeaf, err := tempLeaf(name, "write", ".tmp")
	if err != nil {
		return files.WriteResult{}, opFailed("Random")
	}
	recLeaf := strings.Replace(tmpLeaf, ".webssh-write-", ".webssh-recovery-", 1)
	recLeaf = strings.TrimSuffix(recLeaf, ".tmp") + ".bak"
	tmp, err := sibling(parts, tmpLeaf)
	if err != nil {
		return files.WriteResult{}, fault.Wrap(fault.InvalidRequest, err, "The path is invalid.")
	}
	rec, err := sibling(parts, recLeaf)
	if err != nil {
		return files.WriteResult{}, fault.Wrap(fault.InvalidRequest, err, "The path is invalid.")
	}
	t, err := b.open(ctx, tmp, accessCreateMove, fileCreate, 0, 0, kindFile)
	if err != nil {
		return files.WriteResult{}, err
	}
	defer t.close()
	res, err := b.copyIn(ctx, t, src, o)
	if err != nil {
		if !b.discard(t) {
			return files.WriteResult{}, recoveryRequired(msgTempRemains, tmpLeaf)
		}
		return files.WriteResult{}, err
	}

	// 1. The target moves to the recovery name.
	switch err := b.move(ctx, dest, parts, rec); {
	case isCode(err, fault.OutcomeUnknown):
		return files.WriteResult{}, recoveryRequired(msgSaveUncertain, tmpLeaf, recLeaf)
	case err != nil:
		if !b.discard(t) {
			return files.WriteResult{}, recoveryRequired(msgTempRemains, tmpLeaf)
		}
		return files.WriteResult{}, err
	}
	// 2. The new file takes the target name.
	switch err := b.move(ctx, t, tmp, parts); {
	case isCode(err, fault.OutcomeUnknown):
		return files.WriteResult{}, recoveryRequired(msgReplaceUncertain, tmpLeaf, recLeaf)
	case err != nil:
		if b.move(ctx, dest, rec, parts) != nil {
			return files.WriteResult{}, recoveryRequired(msgRollbackFailed, tmpLeaf, recLeaf)
		}
		if !b.discard(t) {
			return files.WriteResult{}, recoveryRequired(msgRestoredTemp, tmpLeaf)
		}
		return files.WriteResult{}, fault.Wrap(fault.SMBRecoverableReplaceFail, err, msgRestored)
	}
	// 3. The new bytes own the target; the backup goes. From here on
	// nothing moves the installed file again.
	if !b.discard(dest) {
		res.Warning = files.WarningRecoveryBackupRetained
		res.RecoveryLeaves = []string{recLeaf}
	}
	return res, nil
}

// move renames the object of h from its current name to to under the
// mutation deadline, reconciling a lost reply through the handle; a
// rename found not carried out is a plain failure.
func (b *Backend) move(ctx context.Context, h *handle, from, to []string) error {
	if err := b.alive(); err != nil {
		return err
	}
	mctx, cancel := context.WithTimeout(ctx, b.mutation)
	defer cancel()
	return b.reconcile(h.rename(mctx, to, false), func() (bool, bool) {
		switch h.location(to, from) {
		case 0:
			return true, true
		case 1:
			return false, true
		}
		return false, false
	})
}
