package transfer

import (
	"strings"
	"sync"
	"time"

	"github.com/bifrost0x/webssh/internal/files"
)

// ProgressInterval is the least time between two progress events of one
// transfer (app/transfer_progress.py).
const ProgressInterval = 250 * time.Millisecond

// throttle decides which progress updates of one transfer are sent: the
// first always, then at most one per interval, and one more at the end
// when an update was skipped.
type throttle struct {
	now     func() time.Time
	last    time.Time
	sent    bool
	pending bool
}

func (t *throttle) ready() bool {
	now := t.now()
	if !t.sent || now.Sub(t.last) >= ProgressInterval {
		t.last, t.sent, t.pending = now, true, false
		return true
	}
	t.pending = true
	return false
}

// flush reports whether an update is outstanding.
func (t *throttle) flush() bool {
	p := t.pending
	t.pending = false
	return p
}

// auditOp records one transfer as FILE_SOURCE_OPERATION with the target
// fields of the Python release; never a path, only the base name.
func (m *Manager) auditOp(r *record, username, op, result string, size int64, extra ...any) {
	if m.o.Audit == nil {
		return
	}
	kv := []any{"user", username, "operation", op, "result", strings.ToUpper(result)}
	kv = append(kv, m.target(r.owner, r.sourceID)...)
	kv = append(kv, "filename", auditName(r), "size", size)
	m.o.Audit.Security("FILE_SOURCE_OPERATION", append(kv, extra...)...)
}

func auditName(r *record) string {
	if r.archive {
		return folderName(r.path) + ".zip"
	}
	return baseName(r.path)
}

// target are the audit fields of a source: kind, host and share.
func (m *Manager) target(o principalKey, sourceID string) []any {
	var d files.Descriptor
	if m.o.Describe != nil {
		d, _ = m.o.Describe(o.userID, o.session, sourceID)
	}
	kind, host, share := "sftp", d.Endpoint, any(nil)
	if d.Kind == files.KindSMB {
		kind = "smb"
		if i := strings.LastIndexByte(d.Endpoint, '/'); i > 0 {
			host, share = d.Endpoint[:i], d.Endpoint[i+1:]
		}
	}
	return []any{"source_kind", kind, "target_host", host, "share", share}
}

// progressSender sends throttled progress events of one transfer.
type progressSender struct {
	m  *Manager
	r  *record
	mu sync.Mutex
	t  throttle
	ev Progress
}

func (m *Manager) progress(r *record, total int64) *progressSender {
	return &progressSender{m: m, r: r, t: throttle{now: m.o.Now},
		ev: Progress{TransferID: r.id, Direction: r.direction, Total: total, Copy: r.copy}}
}

// update reports transferred bytes; name and total change for copies.
func (s *progressSender) update(transferred, total int64, name string) {
	s.mu.Lock()
	s.ev.Transferred, s.ev.Filename = transferred, name
	if total >= 0 {
		s.ev.Total = total
	}
	send, ev := s.t.ready(), s.ev
	s.mu.Unlock()
	if send {
		s.m.o.Events.Progress(s.r.owner.userID, ev)
	}
}

// done sends the last update when one was skipped.
func (s *progressSender) done() {
	s.mu.Lock()
	send, ev := s.t.flush(), s.ev
	s.mu.Unlock()
	if send {
		s.m.o.Events.Progress(s.r.owner.userID, ev)
	}
}
