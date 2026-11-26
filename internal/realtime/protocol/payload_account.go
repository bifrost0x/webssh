package protocol

import (
	"unicode/utf8"

	"github.com/bifrost0x/webssh/internal/fault"
)

// SettingsTheme sets the user's theme (as today: set_theme).
type SettingsTheme struct {
	Theme string `json:"theme"`
}

// SettingsConfirmClose sets confirm_session_close.
type SettingsConfirmClose struct {
	Enabled bool `json:"enabled"`
}

// SettingsDisconnectAction sets disconnect_session_action.
type SettingsDisconnectAction struct {
	Action string `json:"action"`
}

// MaxNoteRunes bounds a note (Python: 100000 characters).
const MaxNoteRunes = 100_000

// NotesSave stores the user's note without a host (as today:
// save_notepad). Notes of saved hosts use the same model (D-11) but are not
// part of schema v1.
type NotesSave struct {
	Text string `json:"text"`
}

// Validate implements Validator.
func (r *NotesSave) Validate() error {
	if utf8.RuneCountInString(r.Text) > MaxNoteRunes {
		return fault.New(fault.TooLarge, "Notepad content too large (max 100000 characters)")
	}
	return nil
}

// Note is the result of notes.get (request payload Empty) and notes.save.
type Note struct {
	Text string `json:"text"`
}
