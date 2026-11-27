package automation

import (
	"context"
	"encoding/json/jsontext"
	"strconv"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/pyjson"
)

// scheduleApproval is what a user approved for a schedule, with the
// bindings that end the approval (migration specification 4.3): the
// frozen run, the account tuple (incarnation, sign-in generation,
// sign-out generation), the automation policy revision and the binding to
// the saved passwords of its password hops (null without any). Stale
// marks a migrated approval that was no longer valid in the Python
// release; it fails like one.
type scheduleApproval struct {
	Book       jsontext.Value    `json:"book"`
	Targets    []jsontext.Value  `json:"targets"`
	KeyDigests map[string]string `json:"key_digests"`
	Binding    jsontext.Value    `json:"vault_generation"`
	Account    jsontext.Value    `json:"account"`
	Policy     string            `json:"policy"`
	Stale      bool              `json:"stale,omitzero"`
}

func (a scheduleApproval) snapshot() Snapshot {
	return Snapshot{Book: a.Book, Targets: a.Targets, KeyDigests: a.KeyDigests}
}

// incarnation is the first member of the account tuple; the schedules of
// an earlier account with the same id are not this account's.
func (a scheduleApproval) incarnation() string {
	items, _ := pyjson.Items(a.Account)
	if len(items) == 0 {
		return ""
	}
	s, _ := text(items[0])
	return s
}

// accountTuple is the stored account binding.
func accountTuple(b AccountBinding) jsontext.Value {
	return pyjson.Array([]jsontext.Value{
		pyjson.String(b.Incarnation),
		jsontext.Value(strconv.FormatInt(b.AuthGeneration, 10)),
		pyjson.String(b.Epoch),
	})
}

// AccountTuple is the stored form of an account binding (the migration
// writes approvals with it).
func AccountTuple(b AccountBinding) jsontext.Value { return accountTuple(b) }

// sameJSON compares two JSON values by meaning (member order and number
// spelling aside), as Python compared the stored dicts.
func sameJSON(a, b jsontext.Value) bool {
	if len(a) == 0 || len(b) == 0 {
		return len(a) == len(b)
	}
	x, y := a.Clone(), b.Clone()
	return x.Canonicalize() == nil && y.Canonicalize() == nil && string(x) == string(y)
}

func text(v jsontext.Value) (string, bool) {
	if v.Kind() != '"' {
		return "", false
	}
	var b []byte
	b, err := jsontext.AppendUnquote(b, v)
	return string(b), err == nil
}

func member(v jsontext.Value, name string) string {
	m, _ := pyjson.Get(v, name)
	s, _ := text(m)
	return s
}

// hops returns every frozen SSH hop of the targets, each target's jump
// host first and each hop once (connection_resources of
// app/automation_service.py).
func hops(targets []jsontext.Value) []jsontext.Value {
	seen := map[string]bool{}
	var out []jsontext.Value
	for _, t := range targets {
		for _, item := range []jsontext.Value{routeOf(t), t} {
			if item == nil {
				continue
			}
			id := member(item, "id")
			if !seen[id] {
				seen[id] = true
				out = append(out, item)
			}
		}
	}
	return out
}

func routeOf(t jsontext.Value) jsontext.Value {
	r, ok := pyjson.Get(t, "route")
	if !ok || r.Kind() != '{' {
		return nil
	}
	return r
}

// passwordHops are the hops that sign in with a saved password.
func passwordHops(targets []jsontext.Value) []jsontext.Value {
	var out []jsontext.Value
	for _, h := range hops(targets) {
		if member(h, "auth_type") == "password" {
			out = append(out, h)
		}
	}
	return out
}

// displayTarget is display_target of the Python release: the members the
// page shows for a frozen target.
func displayTarget(t jsontext.Value) jsontext.Value {
	get := func(name string, def jsontext.Value) jsontext.Value {
		if v, ok := pyjson.Get(t, name); ok {
			return v
		}
		return def
	}
	null := jsontext.Value("null")
	return pyjson.Object([]pyjson.Member{
		{Name: "id", Value: get("id", null)}, {Name: "name", Value: get("name", null)},
		{Name: "host", Value: get("host", null)}, {Name: "port", Value: get("port", jsontext.Value("22"))},
		{Name: "username", Value: get("username", null)}, {Name: "group", Value: get("group", null)},
	})
}

// binding is the current approval binding of an account: account tuple
// and policy revision. Locked or deleted accounts and a disabled policy
// fail.
func (s *Schedules) binding(ctx context.Context, userID int64) (jsontext.Value, string, error) {
	acc, err := s.o.Accounts.ScheduleAccount(ctx, userID)
	if err != nil {
		if fault.CodeOf(err) == fault.NotFound {
			return nil, "", fault.New(fault.AuthenticationNeeded, "")
		}
		return nil, "", storageFault(err)
	}
	if acc.Locked {
		return nil, "", fault.New(fault.AuthenticationNeeded, "")
	}
	policy, err := s.policy(ctx)
	if err != nil {
		return nil, "", err
	}
	return accountTuple(acc), policy, nil
}

// policy returns the automation policy revision; automation must be on.
func (s *Schedules) policy(ctx context.Context) (string, error) {
	enabled, revision, err := s.o.Policy.AutomationPolicy(ctx)
	if err != nil {
		return "", storageFault(err)
	}
	if !enabled {
		return "", fault.New(fault.AutomationDisabled, "")
	}
	return revision, nil
}

// passwordBinding is the binding of the snapshot's password hops, null
// without any.
func (s *Schedules) passwordBinding(ctx context.Context, userID int64, targets []jsontext.Value) (jsontext.Value, error) {
	ph := passwordHops(targets)
	if len(ph) == 0 {
		return jsontext.Value("null"), nil
	}
	if s.o.Passwords == nil {
		return nil, fault.New(fault.CredentialsDisabled, "")
	}
	return s.o.Passwords.ScheduleBinding(ctx, userID, ph)
}

// validateApproval is _validate_snapshot: the approval holds only while
// the account, the policy, the frozen run and the password binding are
// unchanged. Any difference is preview_changed.
func (s *Schedules) validateApproval(ctx context.Context, userID int64, a scheduleApproval) error {
	changed := fault.New(fault.PreviewChanged, "")
	if a.Stale {
		return changed
	}
	account, policy, err := s.binding(ctx, userID)
	if err != nil {
		return err
	}
	if !sameJSON(account, a.Account) || policy != a.Policy {
		return changed
	}
	if err := s.o.Workflows.Current(ctx, userID, a.snapshot()); err != nil {
		return err
	}
	b, err := s.passwordBinding(ctx, userID, a.Targets)
	if err != nil {
		return err
	}
	if !sameJSON(b, a.Binding) {
		return changed
	}
	return nil
}
