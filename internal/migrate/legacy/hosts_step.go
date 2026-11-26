package legacy

import (
	"context"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/bifrost0x/webssh/internal/hosts"
	"github.com/bifrost0x/webssh/internal/pyjson"
	"github.com/bifrost0x/webssh/internal/store"
)

// hostsStep migrates entity E19, the saved hosts of profiles.json (schema
// 0 to 3, lifted in memory), and with the same import the jump hosts
// (E20), SOCKS5 proxies (E21) and workspace presets (A06) of each account
// through hosts.Import. Records keep their fields, unknown ones included,
// in their order. E20, E21, A06 and A11 verify their part separately.
type hostsStep struct {
	limits hosts.Limits
	users  []userHosts
}

type userHosts struct {
	id     int64
	legacy hosts.Legacy
	flags  []string
	result hosts.ImportReport
}

func (*hostsStep) Entity() string { return "E19" }

func (*hostsStep) Version() int { return 1 }

func (s *hostsStep) Read(ctx context.Context, src *Source) error {
	var err error
	s.users, err = readUserHosts(ctx, src)
	return err
}

// readUserHosts reads the host stores of every account.
func readUserHosts(ctx context.Context, src *Source) ([]userHosts, error) {
	rows, err := src.AccountRows(ctx)
	if err != nil {
		return nil, err
	}
	var out []userHosts
	for _, a := range rows {
		u := userHosts{id: a.ID}
		for _, part := range []struct {
			store, list string
			into        *[]jsontext.Value
		}{
			{"profiles", "profiles", &u.legacy.Profiles},
			{"jump_hosts", "jump_hosts", &u.legacy.JumpHosts},
			{"socks_proxies", "socks_proxies", &u.legacy.SOCKSProxies},
		} {
			doc, found, err := userStore(src, a.ID, part.store)
			if err != nil {
				return nil, err
			}
			if !found {
				continue
			}
			if *part.into, err = doc.RawList(part.list); err != nil {
				return nil, &StepError{UserID: a.ID, Record: part.store, Err: err}
			}
			u.flags = append(u.flags, documentFlags(doc)...)
		}
		settingsDoc, found, err := userStore(src, a.ID, "settings")
		if err != nil {
			return nil, err
		}
		if found {
			if v, ok := pyjson.Get(settingsDoc.Raw, "workspace_presets"); ok {
				u.legacy.WorkspacePresets = v
			}
		}
		out = append(out, u)
	}
	return out, nil
}

func (s *hostsStep) Write(ctx context.Context, tx *store.Tx, _ Sealer) error {
	for i := range s.users {
		u := &s.users[i]
		var err error
		if u.result, err = hosts.Import(ctx, tx, u.id, u.legacy, s.limits); err != nil {
			return &StepError{UserID: u.id, Record: "profiles.json", Err: err}
		}
	}
	return nil
}

// Verify reads every account's saved hosts back. They are byte for byte
// the legacy records, apart from identity facts Python itself drops when
// it loads the store; for an account with such facts the ids and their
// order are compared.
func (s *hostsStep) Verify(ctx context.Context, tx *store.Tx, _ Opener) error {
	for _, u := range s.users {
		got, err := hosts.Export(ctx, tx, u.id)
		if err != nil {
			return &StepError{UserID: u.id, Err: err}
		}
		same := sameRecords(got.Profiles, u.legacy.Profiles)
		if u.result.DroppedFacts > 0 {
			same = sameExceptDropped(got.Profiles, u.legacy.Profiles, u.result.DroppedFacts)
		}
		if !same {
			return &StepError{UserID: u.id, Record: "profiles.json", Err: errors.New("legacy: the stored saved hosts differ")}
		}
	}
	return nil
}

func sameRecords(a, b []jsontext.Value) bool {
	return slices.EqualFunc(a, b, func(x, y jsontext.Value) bool { return string(x) == string(y) })
}

// sameExceptDropped compares stored and legacy profiles field by field
// when Python drops stored host facts on load: every stored field equals
// the legacy one in the legacy order, and exactly dropped legacy fields
// are missing.
func sameExceptDropped(got, legacy []jsontext.Value, dropped int) bool {
	if len(got) != len(legacy) {
		return false
	}
	missing := 0
	for i := range got {
		g, ok1 := pyjson.Members(got[i])
		l, ok2 := pyjson.Members(legacy[i])
		if !ok1 || !ok2 {
			return false
		}
		j := 0
		for _, m := range l {
			if j < len(g) && g[j].Name == m.Name {
				if string(g[j].Value) != string(m.Value) {
					return false
				}
				j++
				continue
			}
			missing++
		}
		if j != len(g) {
			return false
		}
	}
	return missing == dropped
}

func (s *hostsStep) Report() StepReport {
	r := StepReport{Entity: "E19", Version: 1}
	for _, u := range s.users {
		r.Read += len(u.legacy.Profiles)
		r.Written += len(u.legacy.Profiles)
		for _, f := range slices.Compact(slices.Sorted(slices.Values(u.flags))) {
			r.Flagged = append(r.Flagged, Flag{UserID: u.id, Reason: f})
		}
		if u.result.DroppedFacts > 0 {
			r.Notes = append(r.Notes, fmt.Sprintf("user %d: %d stored host facts dropped as the Python release drops them; they are detected again", u.id, u.result.DroppedFacts))
		}
		for _, id := range u.result.IDNAHosts {
			r.Flagged = append(r.Flagged, Flag{UserID: u.id, ID: id, Reason: "host_needs_idna: this preview cannot connect to the host name"})
		}
		if len(u.result.OverLimit) > 0 {
			r.Warnings = append(r.Warnings, Warning{Code: "store_over_limit", UserID: u.id,
				Message: "kept whole above the current limit, can only shrink: " + strings.Join(u.result.OverLimit, ", ")})
		}
	}
	return r
}
