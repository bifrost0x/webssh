package terminal

import (
	"slices"
	"sync"
	"testing"

	"github.com/bifrost0x/webssh/internal/principal"
)

type recordingAudit struct {
	mu     sync.Mutex
	events []string
	kv     [][]any
}

func (a *recordingAudit) SecurityWarning(event string, kv ...any) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, event)
	a.kv = append(a.kv, kv)
}

func (a *recordingAudit) snapshot() ([]string, [][]any) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Clone(a.events), slices.Clone(a.kv)
}

// A tmux session whose end is asked for but cannot be confirmed (here a
// detached one on a password change) reaches the security audit log.
func TestTmuxNotEndedIsAudited(t *testing.T) {
	r := newTmuxRig(t)
	audit := &recordingAudit{}
	r.m.audit = audit
	r.seed(t, detachedRow("detached", "webssh_detached"))
	r.m.Revoked(principal.Revocation{SessionID: "b", UserID: 1, Reason: principal.ReasonPasswordChanged})
	eventually(t, "audit event", func() bool { e, _ := audit.snapshot(); return len(e) > 0 })
	events, kv := audit.snapshot()
	if events[0] != "TMUX_SESSION_NOT_ENDED" || !slices.Contains(kv[0], "detached") || !slices.Contains(kv[0], "webssh_detached") {
		t.Fatalf("audit %v %v", events, kv)
	}
}

// An account deletion removes every row of the account right after it
// published the lock (ID4). The warning for a detached tmux session must
// be written before Revoked returns, or the sweep would remove the row
// first and the warning would be lost.
func TestTmuxNotEndedIsAuditedBeforeAnAccountSweep(t *testing.T) {
	r := newTmuxRig(t)
	audit := &recordingAudit{}
	r.m.audit = audit
	r.seed(t, detachedRow("detached", "webssh_detached"))
	r.m.Revoked(principal.Revocation{UserID: 1, Reason: principal.ReasonAccountLocked})
	// What accounts.TableSweep does in the deletion's second step.
	err := r.m.store.db.Write(t.Context(), func(tx *storeTx) error {
		_, err := tx.ExecContext(t.Context(), `DELETE FROM terminal_persistent_sessions WHERE user_id = 1`)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	events, kv := audit.snapshot()
	if len(events) != 1 || events[0] != "TMUX_SESSION_NOT_ENDED" || !slices.Contains(kv[0], "webssh_detached") {
		t.Fatalf("audit before the sweep: %v %v", events, kv)
	}
}
