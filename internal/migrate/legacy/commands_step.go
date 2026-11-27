package legacy

import (
	"context"
	"encoding/json/jsontext"
	"errors"

	"github.com/bifrost0x/webssh/internal/commands"
	"github.com/bifrost0x/webssh/internal/pyjson"
	"github.com/bifrost0x/webssh/internal/store"
)

// AddCommands registers the steps of the area "commands": the user
// commands (E26) and the command sets (E27), which the M1 release keeps
// in place.
func AddCommands(r *Registry) error {
	r.Schemas(commands.Schema())
	return errors.Join(
		r.Add(GroupCommands, func() Step { return &commandsStep{} }),
		r.Add(GroupCommands, func() Step { return &commandSetsStep{} }),
	)
}

// commandsStep migrates E26: users/user_N/commands.json, a list or the
// legacy object {"schema_version": 1|2, "commands": [...]}, verbatim and
// in list order. The commands are written together with the sets of the
// same user by commandSetsStep, so a set never refers to a command that
// is not there yet; this step reads and verifies them.
type commandsStep struct {
	users []commandUser
	flags []Flag
	read  int
}

type commandUser struct {
	id      int64
	records []jsontext.Value
}

func (*commandsStep) Entity() string { return "E26" }

func (*commandsStep) Version() int { return 1 }

func (*commandsStep) accountScoped() bool { return true }

func (s *commandsStep) Read(ctx context.Context, src *Source) error {
	var err error
	s.users, s.flags, s.read, err = readCommandStore(ctx, src, "commands", "", "commands.json")
	return err
}

func (s *commandsStep) Write(ctx context.Context, tx *store.Tx, _ Sealer) error {
	for _, u := range s.users {
		_, sets, err := commands.StoredTx(ctx, tx, u.id)
		if err != nil {
			return &StepError{UserID: u.id, Err: err}
		}
		if err := commands.ImportTx(ctx, tx, u.id, u.records, sets); err != nil {
			return &StepError{UserID: u.id, Record: "commands.json", Err: err}
		}
	}
	return nil
}

// Verify reads every command back: the same records byte for byte, in
// the same order.
func (s *commandsStep) Verify(ctx context.Context, tx *store.Tx, _ Opener) error {
	for _, u := range s.users {
		got, _, err := commands.StoredTx(ctx, tx, u.id)
		if err != nil {
			return &StepError{UserID: u.id, Err: err}
		}
		if !sameRecords(got, u.records) {
			return &StepError{UserID: u.id, Record: "commands.json", Err: errors.New("legacy: the stored commands differ")}
		}
	}
	return nil
}

func (s *commandsStep) Report() StepReport {
	return StepReport{Entity: "E26", Version: 1, Read: s.read, Written: s.read, Flagged: s.flags,
		accountNote: "commands taken over verbatim for %d accounts", accounts: len(s.users)}
}

// commandSetsStep migrates E27: users/user_N/command_sets.json verbatim
// (inline, library and argv steps, parameters, the sudo flag and members
// this release does not know). Verify also resolves every set the way the
// library lists it, so a set whose commands did not arrive is found.
type commandSetsStep struct {
	users []commandUser
	flags []Flag
	read  int
}

func (*commandSetsStep) Entity() string { return "E27" }

func (*commandSetsStep) Version() int { return 1 }

func (*commandSetsStep) accountScoped() bool { return true }

func (s *commandSetsStep) Read(ctx context.Context, src *Source) error {
	var err error
	s.users, s.flags, s.read, err = readCommandStore(ctx, src, "command_sets", "command_sets", "command_sets.json")
	return err
}

func (s *commandSetsStep) Write(ctx context.Context, tx *store.Tx, _ Sealer) error {
	for _, u := range s.users {
		cmds, _, err := commands.StoredTx(ctx, tx, u.id)
		if err != nil {
			return &StepError{UserID: u.id, Err: err}
		}
		if err := commands.ImportTx(ctx, tx, u.id, cmds, u.records); err != nil {
			return &StepError{UserID: u.id, Record: "command_sets.json", Err: err}
		}
	}
	return nil
}

func (s *commandSetsStep) Verify(ctx context.Context, tx *store.Tx, _ Opener) error {
	for _, u := range s.users {
		_, got, err := commands.StoredTx(ctx, tx, u.id)
		if err != nil {
			return &StepError{UserID: u.id, Err: err}
		}
		if !sameRecords(got, u.records) {
			return &StepError{UserID: u.id, Record: "command_sets.json", Err: errors.New("legacy: the stored command sets differ")}
		}
		for _, rec := range got {
			id := setID(rec)
			if id == "" {
				continue
			}
			if _, _, err := commands.ResolveStoredTx(ctx, tx, u.id, id, false); err != nil {
				return &StepError{UserID: u.id, Record: id, Err: err}
			}
		}
	}
	return nil
}

func (s *commandSetsStep) Report() StepReport {
	return StepReport{Entity: "E27", Version: 1, Read: s.read, Written: s.read, Flagged: s.flags,
		accountNote: "command sets taken over verbatim for %d accounts", accounts: len(s.users)}
}

// readCommandStore reads one of the two stores of every account.
func readCommandStore(ctx context.Context, src *Source, store, listKey, file string) ([]commandUser, []Flag, int, error) {
	rows, err := src.AccountRows(ctx)
	if err != nil {
		return nil, nil, 0, err
	}
	var users []commandUser
	var flags []Flag
	read := 0
	for _, a := range rows {
		doc, found, err := userStore(src, a.ID, store)
		if err != nil {
			return nil, nil, 0, err
		}
		if !found {
			continue
		}
		recs, err := doc.RawList(listKey)
		if err != nil {
			return nil, nil, 0, &StepError{UserID: a.ID, Record: file, Err: err}
		}
		for _, f := range documentFlags(doc) {
			flags = append(flags, Flag{UserID: a.ID, ID: file, Reason: f})
		}
		users = append(users, commandUser{id: a.ID, records: recs})
		read += len(recs)
	}
	return users, flags, read, nil
}

// setID is the id of a stored set ("" when it is empty; Python accepts
// such a set but no host can refer to it).
func setID(rec jsontext.Value) string {
	v, _ := pyjson.Get(rec, "id")
	id, _ := pyString(v)
	return id
}
