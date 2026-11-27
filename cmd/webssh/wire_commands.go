package main

import (
	"context"
	"encoding/json/jsontext"
	json "encoding/json/v2"

	cmdlib "github.com/bifrost0x/webssh/internal/commands"
	"github.com/bifrost0x/webssh/internal/config"
	"github.com/bifrost0x/webssh/internal/hostops"
	"github.com/bifrost0x/webssh/internal/hosts"
	"github.com/bifrost0x/webssh/internal/migrate/legacy"
	"github.com/bifrost0x/webssh/internal/pyjson"
	"github.com/bifrost0x/webssh/internal/store"
	"github.com/bifrost0x/webssh/internal/terminal"
)

// commandsArea wires the area "commands" (CM1): commands and command sets (internal/commands).
// CM1 fills in the hooks; no other package edits this file.
func commandsArea() extension {
	return extension{
		name:    "commands",
		schemas: []store.Schema{cmdlib.Schema()},
		prepare: func(sys *system) error {
			s := sys.cfg.Stores
			lib := &cmdlib.Library{DB: sys.db, Refs: profileRefs{sys}, Hosts: commandHosts{sys},
				Limits: cmdlib.Limits{MaxCommands: s.CommandMaxRecords, MaxSets: s.CommandSetMaxRecords,
					MaxSetSteps: s.CommandSetMaxSteps, MaxOSEntries: s.CommandOSMaxEntries,
					StoreMaxBytes: int64(s.CommandStoreMaxBytes), ConfigMaxBytes: int64(s.CommandConfigMaxBytes)}}
			sys.optional.commandLibrary = lib
			sys.optional.hostCommands = lib
			sys.optional.terminalCommands = terminalCommands{lib}
			return nil
		},
		wire: func(sys *system) error {
			sys.realtime.Mount(sys.optional.commandLibrary.Routes()...)
			return nil
		},
		migrate: func(r *legacy.Registry, _ config.Config, _ config.LookupFunc) error {
			return legacy.AddCommands(r)
		},
	}
}

var (
	_ hosts.CommandRefs   = (*cmdlib.Library)(nil)
	_ hostops.CommandSets = (*cmdlib.Library)(nil)
	_ terminal.Commands   = terminalCommands{}
	_ cmdlib.References   = profileRefs{}
	_ cmdlib.TxReferences = profileRefs{}
	_ cmdlib.Profiles     = commandHosts{}
)

// terminalCommands resolves the startup modes command and command_set
// from the owner's library at connect time.
type terminalCommands struct{ lib *cmdlib.Library }

func (t terminalCommands) Command(ctx context.Context, owner int64, commandID string) (string, string, error) {
	return t.lib.Command(ctx, owner, commandID)
}

func (t terminalCommands) ResolveSet(ctx context.Context, owner int64, setID string) (string, error) {
	return t.lib.Resolve(ctx, owner, setID, nil, false)
}

// profileRefs lists the saved hosts that start with a set or a command,
// read in the library's transaction when it has one.
type profileRefs struct{ sys *system }

func (p profileRefs) usages(ctx context.Context, tx *store.Tx, owner int64, field, id string) ([]cmdlib.Usage, error) {
	if id == "" {
		return nil, nil
	}
	l, err := hosts.Export(ctx, tx, owner)
	if err != nil {
		return nil, err
	}
	var out []cmdlib.Usage
	for _, rec := range l.Profiles {
		if text(rec, field) != id {
			continue
		}
		out = append(out, cmdlib.Usage{ID: text(rec, "id"), Name: text(rec, "name"), Type: "profile"})
	}
	return out, nil
}

func (p profileRefs) read(ctx context.Context, owner int64, field, id string) ([]cmdlib.Usage, error) {
	var out []cmdlib.Usage
	err := p.sys.db.Read(ctx, func(tx *store.Tx) error {
		var err error
		out, err = p.usages(ctx, tx, owner, field, id)
		return err
	})
	return out, err
}

func (p profileRefs) SetUsages(ctx context.Context, owner int64, setID string) ([]cmdlib.Usage, error) {
	return p.read(ctx, owner, "command_set_id", setID)
}

func (p profileRefs) CommandUsages(ctx context.Context, owner int64, commandID string) ([]cmdlib.Usage, error) {
	return p.read(ctx, owner, "command_id", commandID)
}

func (p profileRefs) SetUsagesTx(ctx context.Context, tx *store.Tx, owner int64, setID string) ([]cmdlib.Usage, error) {
	return p.usages(ctx, tx, owner, "command_set_id", setID)
}

func (p profileRefs) CommandUsagesTx(ctx context.Context, tx *store.Tx, owner int64, commandID string) ([]cmdlib.Usage, error) {
	return p.usages(ctx, tx, owner, "command_id", commandID)
}

// text is a string member of a stored record, or "" (Python compares the
// reference with ==, so a member that is not text matches no id).
func text(rec jsontext.Value, name string) string {
	v, ok := pyjson.Get(rec, name)
	if !ok || v.Kind() != '"' {
		return ""
	}
	var s string
	if err := json.Unmarshal(v, &s); err != nil {
		return ""
	}
	return s
}

// commandHosts converts the free startup text of a saved host.
type commandHosts struct{ sys *system }

func (c commandHosts) LegacyStartup(ctx context.Context, owner int64, profileID string) (string, bool, bool, error) {
	return c.sys.hosts.LegacyStartup(ctx, owner, profileID)
}

func (c commandHosts) AssignSet(ctx context.Context, owner int64, profileID, setID string) (jsontext.Value, error) {
	return c.sys.hosts.AssignCommandSet(ctx, owner, profileID, setID)
}
