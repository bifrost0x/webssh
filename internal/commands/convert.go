package commands

import (
	"context"
	"encoding/json/jsontext"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
)

// Profiles reads and changes the startup of a saved host for the
// conversion of its free startup text into a set (provided in cmd/webssh
// over internal/hosts).
type Profiles interface {
	// LegacyStartup returns the stored startup_commands of the host
	// (absent or not text is ok false) and whether it already names a
	// set; a host the user does not own is not_found.
	LegacyStartup(ctx context.Context, owner int64, profileID string) (text string, ok, usesSet bool, err error)
	// AssignSet makes the set the startup of the host and returns the
	// host as the page shows it (assign_command_set); the free text stays
	// stored as before.
	AssignSet(ctx context.Context, owner int64, profileID, setID string) (jsontext.Value, error)
}

// Convert is convert_legacy_command_set: the host's free startup text
// becomes a new set with one inline step, and the host starts with it.
func (l *Library) Convert(ctx context.Context, userID int64, req protocol.CommandSetConvert) (jsontext.Value, jsontext.Value, error) {
	hosts := l.Hosts
	if hosts == nil {
		return nil, nil, fault.New(fault.NotAvailableInPreview, "")
	}
	idValue, _ := decode(req.ProfileID)
	profileID, _ := idValue.(string)
	if profileID == "" {
		return nil, nil, notFound("Profile not found")
	}
	text, ok, usesSet, err := hosts.LegacyStartup(ctx, userID, profileID)
	if err != nil {
		return nil, nil, err
	}
	if usesSet {
		return nil, nil, invalid("Profile already uses a command set")
	}
	if !ok || pyStrip(text) == "" {
		return nil, nil, invalid("Profile has no legacy startup commands")
	}
	description := req.Description
	if len(description) == 0 {
		description = rawString("")
	}
	steps := rawValue([]any{map[string]any{"type": "inline", "command": text}})
	set, err := l.SaveSet(ctx, userID, protocol.CommandSetSave{Name: req.Name, Description: description,
		UseSudo: jsontext.Value("false"), Steps: steps})
	if err != nil {
		return nil, nil, err
	}
	setID, _ := recordID(set)
	profile, err := hosts.AssignSet(ctx, userID, profileID, setID)
	if err != nil {
		return nil, nil, err
	}
	return set, profile, nil
}
