package transfer

import (
	"context"

	"github.com/bifrost0x/webssh/internal/files"
)

// runCopy is the background job of one host-to-host copy. It owns r until
// the final state.
func (m *Manager) runCopy(ctx context.Context, c files.Caller, r *record, src, dst files.Backend) {
	defer m.work.Done()
	defer r.cancel(nil)
	progress := m.progress(r, 0)
	cp := &copier{
		src: src, dst: dst, sameSource: r.sourceID == r.destID, fold: dst.Capabilities().CaseInsensitive,
		replace: r.policy == ConflictReplace, chunk: m.o.ChunkSize,
		bud: &budget{maxBytes: m.o.Limits.MaxArchive, maxMembers: m.o.Limits.MaxMembers, maxDepth: m.o.Limits.MaxDepth},
		progress: func(path string, total, size int64) {
			// Python reported the bytes of the whole copy against the size
			// of the current file.
			progress.update(total, max(total, size), baseName(path))
		},
	}
	err := cp.run(ctx, r.path, r.destPath)
	progress.done()
	dest := m.target(r.owner, r.destID)
	extra := []any{"destination_target_host", dest[3], "destination_share", dest[5], "destination_filename", baseName(r.destPath)}
	if err == nil {
		if m.finish(r, Completed, nil, true) {
			m.auditOp(r, c.P.Username, "server_to_server_copy", "COMPLETED", cp.bud.used, extra...)
		}
		return
	}
	f := endedBy(ctx, err, opCopy)
	state := Failed
	if f.Code == errCancelled.Code {
		state = Cancelled
	}
	if m.finish(r, state, &f, true) {
		m.o.Logger.Info("host-to-host copy ended", "user_id", c.P.UserID, "transfer_id", r.id, "code", string(f.Code))
		m.auditOp(r, c.P.Username, "server_to_server_copy", string(f.Code), cp.bud.used, extra...)
	}
}
