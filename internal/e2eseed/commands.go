package e2eseed

import (
	"context"
	"encoding/json/jsontext"
	"fmt"
	"time"

	"github.com/bifrost0x/webssh/internal/pyjson"
)

// Commands stores the seeded commands and command sets of an account as
// the Python store holds them (internal/commands).
type Commands interface {
	SeedCommands(ctx context.Context, owner int64, commands, sets []jsontext.Value) error
}

// applyCommands is the commands half of run_app.py: every entry without
// its account, a command with isSystem false, its user id and createdAt,
// a set with created_at and updated_at, saved per account in
// first-appearance order before the profiles that refer to them.
func applyCommands(ctx context.Context, s *Seed, st Commands, users map[string]int64, now time.Time) error {
	type records struct{ commands, sets []jsontext.Value }
	var order []string
	byAccount := map[string]*records{}
	entry := func(account string) *records {
		r, ok := byAccount[account]
		if !ok {
			r = &records{}
			byAccount[account] = r
			order = append(order, account)
		}
		return r
	}
	stamp := pyjson.String(isoUTC(now))
	for _, e := range s.Commands {
		rec, err := ownedRecord(e)
		if err != nil {
			return fmt.Errorf("command: %w", err)
		}
		rec = pyjson.Set(rec, "isSystem", jsontext.Value("false"))
		rec = pyjson.Set(rec, "userId", jsontext.Value(fmt.Sprint(users[e.Account])))
		rec = pyjson.Set(rec, "createdAt", stamp)
		r := entry(e.Account)
		r.commands = append(r.commands, pyjson.Object(rec))
	}
	for _, e := range s.CommandSets {
		rec, err := ownedRecord(e)
		if err != nil {
			return fmt.Errorf("command set: %w", err)
		}
		rec = pyjson.Set(rec, "created_at", stamp)
		rec = pyjson.Set(rec, "updated_at", stamp)
		r := entry(e.Account)
		r.sets = append(r.sets, pyjson.Object(rec))
	}
	for _, account := range order {
		r := byAccount[account]
		if err := st.SeedCommands(ctx, users[account], r.commands, r.sets); err != nil {
			return fmt.Errorf("commands of %s: %w", account, err)
		}
	}
	return nil
}

// ownedRecord is the entry as written without its account member.
func ownedRecord(e OwnedEntry) ([]pyjson.Member, error) {
	doc, _, err := pyjson.Load(e.Raw)
	if err != nil {
		return nil, err
	}
	members, ok := pyjson.Members(doc)
	if !ok {
		return nil, fmt.Errorf("entry of %s is not an object", e.Account)
	}
	return pyjson.Delete(members, "account"), nil
}

// isoUTC is datetime.now(timezone.utc).isoformat().
func isoUTC(t time.Time) string {
	t = t.UTC()
	s := t.Format("2006-01-02T15:04:05")
	if us := t.Nanosecond() / 1000; us != 0 {
		s += fmt.Sprintf(".%06d", us)
	}
	return s + "+00:00"
}
