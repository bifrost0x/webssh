package hosts

import (
	"context"
	"encoding/json/jsontext"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/store"
)

// CommandRefs checks the command or the command set a saved host starts
// with (validate_configuration of app/post_connect_manager.py), provided
// by internal/commands. It reads the library through the transaction
// that saves the host, so a set deleted at the same moment cannot stay
// referenced.
type CommandRefs interface {
	// CheckCommandTx refuses a command the user cannot use or a parameter
	// override that cannot be appended to it; override is absent (zero
	// length) or the raw member.
	CheckCommandTx(ctx context.Context, tx *store.Tx, owner int64, commandID, override jsontext.Value) error
	// CheckSetTx refuses a set the user does not own or one with
	// parameters, which needs interactive launch.
	CheckSetTx(ctx context.Context, tx *store.Tx, owner int64, setID jsontext.Value) error
}

// checkStartupRefs checks the reference of the startup mode a saved host
// is saved with, when the library is part of the build.
func (s *Service) checkStartupRefs(ctx context.Context, tx *store.Tx, owner int64, p payload) error {
	get := func(name string) (jsontext.Value, bool) { return p[name], p.has(name) }
	modeValue, _ := startupMode(get)
	mode, _ := asString(modeValue)
	switch mode {
	case "command":
		return s.Commands.CheckCommandTx(ctx, tx, owner, p.get("command_id"), p["parameters_override"])
	case "command_set":
		return s.Commands.CheckSetTx(ctx, tx, owner, p.get("command_set_id"))
	}
	return nil
}

// LegacyStartup returns the free startup text of a saved host and
// whether it already starts with a set (convert_legacy_command_set).
func (s *Service) LegacyStartup(ctx context.Context, owner int64, profileID string) (text string, ok, usesSet bool, err error) {
	err = s.DB.Read(ctx, func(tx *store.Tx) error {
		profiles, err := load(ctx, tx, profileTable, owner)
		if err != nil {
			return err
		}
		i := find(profiles, profileID)
		if i < 0 {
			return errProfileNotFound
		}
		p := &profiles[i]
		set, _ := p.get("command_set_id")
		usesSet = truthy(set)
		text, ok = p.str("startup_commands")
		return nil
	})
	return text, ok, usesSet, classify(err, "Failed to load profiles")
}

// AssignCommandSet makes a set the startup of a saved host
// (assign_command_set): the mode becomes command_set and the free text
// stays stored as before. A host in Herdr session mode refuses it.
func (s *Service) AssignCommandSet(ctx context.Context, owner int64, profileID, setID string) (jsontext.Value, error) {
	var saved record
	err := s.DB.Write(ctx, func(tx *store.Tx) error {
		if s.Commands == nil {
			return fault.New(fault.NotAvailableInPreview, "")
		}
		if err := s.Commands.CheckSetTx(ctx, tx, owner, jsonString(setID)); err != nil {
			return err
		}
		all, err := loadStores(ctx, tx, owner)
		if err != nil {
			return err
		}
		profiles := all["profiles"]
		i := find(profiles, profileID)
		if i < 0 {
			return errProfileNotFound
		}
		if v, _ := profiles[i].get("use_herdr"); string(v) == "true" {
			return invalid("Herdr session mode cannot be combined with startup commands")
		}
		next := cloneRecords(profiles)
		next[i].set("startup_mode", jsonString("command_set"))
		next[i].set("command_set_id", jsonString(setID))
		if err := checkBudgets(&next[i], &profiles[i], profileBudgets, true); err != nil {
			return err
		}
		if !validProfile(&next[i]) {
			return fault.New(fault.ValidationError, "Failed to save profile")
		}
		saved = next[i]
		return replace(ctx, tx, profileTable, owner, next)
	})
	if err != nil {
		return nil, classify(err, "Failed to save profile")
	}
	return publicProfile(saved, s.tailscaleAuthorized(ctx)), nil
}
