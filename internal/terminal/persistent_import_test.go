package terminal

import (
	"testing"

	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
)

// The migration keeps the legacy row id, writes the row detached and
// reads every row back with its id; a row id that is not positive or
// already taken is refused.
func TestImportPersistentAtKeepsRowID(t *testing.T) {
	r := newTmuxRig(t)
	first := detachedRow("legacy-7", "webssh_seven")
	first.Connected = true
	second := detachedRow("legacy-3", "webssh_three")
	second.UserID = 2
	err := r.m.store.db.Write(t.Context(), func(tx *storeTx) error {
		if err := ImportPersistentAt(t.Context(), tx, 7, first); err != nil {
			return err
		}
		return ImportPersistentAt(t.Context(), tx, 3, second)
	})
	if err != nil {
		t.Fatal(err)
	}
	var got []ImportedPersistent
	err = r.m.store.db.Read(t.Context(), func(tx *storeTx) error {
		got, err = ImportedPersistentTx(t.Context(), tx)
		return err
	})
	first.Connected = false
	if err != nil || len(got) != 2 || got[0].ID != 3 || got[0].Row != second || got[1].ID != 7 || got[1].Row != first {
		t.Fatalf("read back %+v %v", got, err)
	}
	// A reconnect offer has no connection yet, so no file source
	// (persistent_session_available had none).
	r.m.SetFileSources(func(principal.Principal, protocol.SessionInfo) *protocol.FileSource { return &protocol.FileSource{} })
	if list, err := r.m.Persistent(t.Context(), principalOf(1)); err != nil || len(list) != 1 || list[0].TmuxSessionName != "webssh_seven" || list[0].FileSource != nil {
		t.Fatalf("offer %+v %v", list, err)
	}
	for _, id := range []int64{0, -1, 7} {
		err := r.m.store.db.Write(t.Context(), func(tx *storeTx) error {
			return ImportPersistentAt(t.Context(), tx, id, detachedRow("legacy-x", "webssh_x"))
		})
		if err == nil {
			t.Errorf("row id %d accepted", id)
		}
	}
}
