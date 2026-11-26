package hostops

import (
	"context"
	"strings"
	"testing"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
	"github.com/bifrost0x/webssh/internal/realtime/protocol/protocoltest"
	"github.com/bifrost0x/webssh/internal/store"
	"github.com/bifrost0x/webssh/internal/store/storetest"
)

func routes(n *Notes) map[string]protocol.Route {
	out := map[string]protocol.Route{}
	for _, r := range n.Routes() {
		out[r.Type] = r
	}
	return out
}

func rows(t *testing.T, db *store.DB) int {
	t.Helper()
	var count int
	if err := db.Read(t.Context(), func(tx *store.Tx) error {
		return tx.QueryRowContext(t.Context(), `SELECT count(*) FROM hostops_notes`).Scan(&count)
	}); err != nil {
		t.Fatal(err)
	}
	return count
}

func TestNotepad(t *testing.T) {
	db := storetest.Open(t, Schema())
	n := &Notes{DB: db}
	r := routes(n)
	alice := protocoltest.NewPeer(t, principal.Principal{UserID: 1, SessionID: "a"})
	bob := protocoltest.NewPeer(t, principal.Principal{UserID: 2, SessionID: "b"})
	get := func(peer *protocoltest.Peer) string {
		t.Helper()
		got, err := protocoltest.Call(t.Context(), r[protocol.TypeNotesGet], peer, nil)
		if err != nil {
			t.Fatal(err)
		}
		return string(got)
	}
	if got := get(alice); got != `{"text":""}` {
		t.Fatalf("empty notepad: %s", got)
	}
	text := strings.Repeat("ü", protocol.MaxNoteRunes)
	if _, err := protocoltest.Call(t.Context(), r[protocol.TypeNotesSave], alice, protocol.NotesSave{Text: text}); err != nil {
		t.Fatalf("note at the limit: %v", err)
	}
	if got := get(alice); got != `{"text":"`+text+`"}` {
		t.Fatal("note not stored")
	}
	if got := get(bob); got != `{"text":""}` {
		t.Fatalf("another user's note: %.40s", got)
	}
	_, err := protocoltest.Call(t.Context(), r[protocol.TypeNotesSave], alice, protocol.NotesSave{Text: text + "x"})
	if err == nil || err.Message != "Notepad content too large (max 100000 characters)" {
		t.Fatalf("note over the limit: %+v", err)
	}
	if _, err := protocoltest.Call(t.Context(), r[protocol.TypeNotesSave], alice, protocol.NotesSave{Text: ""}); err != nil {
		t.Fatal(err)
	}
	if rows(t, db) != 0 {
		t.Fatal("an empty note must not keep a row")
	}
	if _, err := n.SaveNote(t.Context(), 1, text+"y"); fault.CodeOf(err) != fault.TooLarge {
		t.Fatalf("service bound: %v", err)
	}
	if !r[protocol.TypeNotesSave].Spec.Mutates || r[protocol.TypeNotesSave].Spec.MaxPayload < 6*protocol.MaxNoteRunes {
		t.Fatal("notes.save must re-check the session and admit a full note")
	}
	if _, err := n.Routes()[0].Run(context.Background(), protocoltest.NewPeer(t, principal.Principal{}), nil); fault.CodeOf(err) != fault.AuthenticationNeeded {
		t.Fatalf("no principal: %v", err)
	}
}

func TestNoteRevisionsAndImport(t *testing.T) {
	db := storetest.Open(t, Schema())
	n := &Notes{DB: db}
	if err := db.Write(t.Context(), func(tx *store.Tx) error {
		if err := ImportNote(t.Context(), tx, 1, "", "legacy pad", 0); err != nil {
			return err
		}
		if err := ImportNote(t.Context(), tx, 1, "profile-1", "host note", 7); err != nil {
			return err
		}
		return ImportNote(t.Context(), tx, 2, "", "", 0) // an empty notepad creates no row
	}); err != nil {
		t.Fatal(err)
	}
	if got, _ := n.Note(t.Context(), 1); got != "legacy pad" {
		t.Fatalf("imported notepad: %q", got)
	}
	if _, err := n.SaveNote(t.Context(), 1, "edited"); err != nil {
		t.Fatal(err)
	}
	var revision int64
	var hostNote string
	if err := db.Read(t.Context(), func(tx *store.Tx) error {
		if err := tx.QueryRowContext(t.Context(), `SELECT revision FROM hostops_notes WHERE user_id = 1 AND profile_id IS NULL`).Scan(&revision); err != nil {
			return err
		}
		return tx.QueryRowContext(t.Context(), `SELECT body FROM hostops_notes WHERE profile_id = 'profile-1'`).Scan(&hostNote)
	}); err != nil {
		t.Fatal(err)
	}
	if revision != 1 || hostNote != "host note" || rows(t, db) != 2 {
		t.Fatalf("revision %d, host note %q, rows %d", revision, hostNote, rows(t, db))
	}
	err := db.Write(t.Context(), func(tx *store.Tx) error { return ImportNote(t.Context(), tx, 1, "", "second", 0) })
	if err == nil {
		t.Fatal("two notes without host for one user")
	}
}
