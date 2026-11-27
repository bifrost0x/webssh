package legacy

import (
	"context"
	"encoding/json/jsontext"
	"errors"

	"github.com/bifrost0x/webssh/internal/hosts"
	"github.com/bifrost0x/webssh/internal/pyjson"
	"github.com/bifrost0x/webssh/internal/store"
)

// hostPart is an entity that E19's import writes together with the saved
// hosts; its step verifies and reports its own part.
type hostPart struct {
	entity string
	note   string
	// pick returns the part of the legacy or stored data to compare.
	pick func(hosts.Legacy) []jsontext.Value
}

var hostPartEntities = []hostPart{
	{entity: "E20", note: "jump hosts taken over verbatim", pick: func(l hosts.Legacy) []jsontext.Value { return l.JumpHosts }},
	{entity: "E21", note: "SOCKS5 proxies taken over verbatim, remote_dns included",
		pick: func(l hosts.Legacy) []jsontext.Value { return l.SOCKSProxies }},
	{entity: "A06", note: "workspace presets taken over verbatim, profile references kept", pick: func(l hosts.Legacy) []jsontext.Value {
		if l.WorkspacePresets == nil {
			return nil
		}
		return []jsontext.Value{l.WorkspacePresets}
	}},
	{entity: "A11", note: "favourite, group and sort order of each saved host kept with the host",
		pick: func(l hosts.Legacy) []jsontext.Value { return organisation(l.Profiles) }},
}

// organisation extracts favorite, group and sort_order of each profile.
func organisation(profiles []jsontext.Value) []jsontext.Value {
	out := make([]jsontext.Value, 0, len(profiles))
	for _, p := range profiles {
		var m []pyjson.Member
		for _, name := range []string{"id", "favorite", "group", "sort_order"} {
			if v, ok := pyjson.Get(p, name); ok {
				m = append(m, pyjson.Member{Name: name, Value: v})
			}
		}
		out = append(out, pyjson.Object(m))
	}
	return out
}

type hostPartStep struct {
	part  hostPart
	users []userHosts
	read  int
}

func (s *hostPartStep) Entity() string { return s.part.entity }

func (*hostPartStep) Version() int { return 1 }

func (*hostPartStep) accountScoped() bool { return true }

func (s *hostPartStep) Read(ctx context.Context, src *Source) error {
	var err error
	if s.users, err = readUserHosts(ctx, src); err != nil {
		return err
	}
	for _, u := range s.users {
		s.read += len(s.part.pick(u.legacy))
	}
	return nil
}

func (*hostPartStep) Write(context.Context, *store.Tx, Sealer) error { return nil }

func (s *hostPartStep) Verify(ctx context.Context, tx *store.Tx, _ Opener) error {
	for _, u := range s.users {
		got, err := hosts.Export(ctx, tx, u.id)
		if err != nil {
			return &StepError{UserID: u.id, Err: err}
		}
		if !sameRecords(s.part.pick(got), s.part.pick(u.legacy)) {
			return &StepError{UserID: u.id, Err: errors.New("legacy: the stored " + s.part.note + " differ")}
		}
	}
	return nil
}

func (s *hostPartStep) Report() StepReport {
	return StepReport{Entity: s.part.entity, Version: 1, Read: s.read, Written: s.read, Notes: []string{s.part.note}}
}
