package hostops

import (
	"context"

	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
)

// maxNotePayload fits a note of MaxNoteRunes characters even when every
// one is sent as a six-byte escape.
const maxNotePayload = 6*protocol.MaxNoteRunes + 1<<10

// Routes are notes.get and notes.save (get_notepad, save_notepad).
func (n *Notes) Routes() []protocol.Route {
	return []protocol.Route{
		protocol.Handle(protocol.TypeNotesGet, protocol.Spec{}, n.handleGet),
		protocol.Handle(protocol.TypeNotesSave, protocol.Spec{Mutates: true, MaxPayload: maxNotePayload}, n.handleSave),
	}
}

func (n *Notes) handleGet(ctx context.Context, _ protocol.Peer, _ protocol.Empty) (protocol.Note, error) {
	p, err := principal.Require(ctx)
	if err != nil {
		return protocol.Note{}, err
	}
	text, err := n.Note(ctx, p.UserID)
	return protocol.Note{Text: text}, err
}

func (n *Notes) handleSave(ctx context.Context, _ protocol.Peer, req protocol.NotesSave) (protocol.Note, error) {
	p, err := principal.Require(ctx)
	if err != nil {
		return protocol.Note{}, err
	}
	text, err := n.SaveNote(ctx, p.UserID, req.Text)
	return protocol.Note{Text: text}, err
}
