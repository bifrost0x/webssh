package commands

import (
	"context"
	"fmt"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/store"
)

// TxReferences is References inside the library's write transaction. A
// References that also implements it is asked there, so that no saved
// host can start to use a set or a command between the check and the
// delete (the coordinator lock of the Python release). The provider in
// cmd/webssh reads the saved hosts through the same transaction.
type TxReferences interface {
	SetUsagesTx(ctx context.Context, tx *store.Tx, userID int64, setID string) ([]Usage, error)
	CommandUsagesTx(ctx context.Context, tx *store.Tx, userID int64, commandID string) ([]Usage, error)
}

func (l *Library) setUsages(ctx context.Context, tx *store.Tx, userID int64, setID string, isText bool) ([]Usage, error) {
	if !isText {
		return nil, nil
	}
	if l.Refs == nil {
		return nil, fault.New(fault.Internal, "")
	}
	var usages []Usage
	var err error
	if t, ok := l.Refs.(TxReferences); ok {
		usages, err = t.SetUsagesTx(ctx, tx, userID, setID)
	} else {
		usages, err = l.Refs.SetUsages(ctx, userID, setID)
	}
	if err != nil {
		return nil, fmt.Errorf("commands: saved hosts that use set: %w", err)
	}
	return usages, nil
}

func (l *Library) commandUsages(ctx context.Context, tx *store.Tx, userID int64, commandID string, isText bool) ([]Usage, error) {
	if !isText {
		return nil, nil
	}
	if l.Refs == nil {
		return nil, fault.New(fault.Internal, "")
	}
	var usages []Usage
	var err error
	if t, ok := l.Refs.(TxReferences); ok {
		usages, err = t.CommandUsagesTx(ctx, tx, userID, commandID)
	} else {
		usages, err = l.Refs.CommandUsages(ctx, userID, commandID)
	}
	if err != nil {
		return nil, fmt.Errorf("commands: saved hosts that use command: %w", err)
	}
	return usages, nil
}

// inUse is the refusal of a delete (in_use): the message of the Python
// release and details.usages, the shown references (at most 20).
func inUse(subject string, count int, kinds map[string]bool, usages any, shown int) error {
	noun := "reference"
	switch {
	case len(kinds) == 1 && kinds["command_set"]:
		noun = "command set"
	case len(kinds) == 1 && kinds["profile"]:
		noun = "profile"
	}
	if count != 1 {
		noun += "s"
	}
	details := ""
	if count > shown {
		details = fmt.Sprintf(" (showing first %d)", shown)
	}
	return &fault.Error{Code: fault.InUse, Message: fmt.Sprintf("%s is used by %d %s%s", subject, count, noun, details),
		Details: map[string]any{"usages": usages}}
}

// usageMaps is the usages member of a refused command delete.
func usageMaps(usages []Usage) []map[string]any {
	out := make([]map[string]any, len(usages))
	for i, u := range usages {
		out[i] = map[string]any{"id": u.ID, "name": u.Name, "type": u.Type}
	}
	return out
}
