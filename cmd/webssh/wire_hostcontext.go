package main

import (
	"context"
	"net/http"

	"github.com/bifrost0x/webssh/internal/audit"
	"github.com/bifrost0x/webssh/internal/auth"
	"github.com/bifrost0x/webssh/internal/auth/stepup"
	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/hostops"
	"github.com/bifrost0x/webssh/internal/hosts"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/ssh/hostkey"
	"github.com/bifrost0x/webssh/internal/vault"
)

// hostcontextArea wires the area "hostcontext" (HO3): host context, global host trust and profile exchange (internal/hostops, internal/ssh/hostkey, internal/hosts).
// HO3 fills in the hooks; no other package edits this file.
//
// The host context checks command-set references with
// hostops.Contexts.Sets, the command library (area "commands").
func hostcontextArea() extension {
	return extension{
		name: "hostcontext",
		wire: func(sys *system) error {
			mux := sys.edge.Mux()
			(&hostkey.GlobalHTTP{Store: sys.hostkeys, StepUp: sys.stepup, Audit: sys.audit,
				Enabled: sys.cfg.Features.HostKeyManagement, Logger: sys.log}).Register(mux)
			contexts := &hostops.Contexts{DB: sys.db, Profiles: sys.hosts}
			if lib := sys.optional.commandLibrary; lib != nil {
				contexts.Sets = lib
			}
			(&hostops.ContextHTTP{Contexts: contexts, Logger: sys.log}).Register(mux)
			limits := sys.factorLimits()
			rule := auth.ParseRule(sys.cfg.RateLimits.SSHKeyList, ruleKeyList)
			(&hosts.ExchangeHTTP{Service: sys.hosts, Keys: usableKeys{sys.vault}, Logger: sys.log,
				Limited: func(r *http.Request, userID int64) bool {
					return limits.UserLimited(r, userID, "profile_exchange_preview", rule)
				}}).Register(mux)
			return nil
		},
	}
}

var (
	_ hostkey.Auditor  = (*audit.Logger)(nil)
	_ hostops.Profiles = (*hosts.Service)(nil)
	_ hosts.UsableKeys = usableKeys{}
	_ hostkey.StepUp   = (*stepup.Service)(nil)
)

// usableKeys adapts the key vault to hosts.UsableKeys. The vault lists
// the keys of the principal in the context, which must be owner: the
// import preview serves only the signed-in account.
type usableKeys struct{ v *vault.Service }

func (u usableKeys) UsableKeys(ctx context.Context, owner int64) ([]hosts.KeyRef, error) {
	p, err := principal.Require(ctx)
	if err != nil {
		return nil, err
	}
	if p.UserID != owner {
		return nil, fault.New(fault.Forbidden, "")
	}
	summaries, err := u.v.List(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]hosts.KeyRef, 0, len(summaries))
	for _, s := range summaries {
		if s.Usable {
			out = append(out, hosts.KeyRef{ID: s.ID, Name: s.Name})
		}
	}
	return out, nil
}
