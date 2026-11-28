package vault

import (
	"context"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"maps"
	"slices"
	"sync"
	"testing"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/pyjson"
	"github.com/bifrost0x/webssh/internal/store"
)

// fakeStores holds the records of the resources per user.
type fakeStores struct {
	mu      sync.Mutex
	records map[int64]*Records
	fail    error
	created int
	// db runs the transaction of CreateResource; refuse fails it before
	// anything is stored; rolledBack counts the records dropped again.
	db         *store.DB
	refuse     error
	rolledBack int
	updated    int
}

func (f *fakeStores) Records(_ context.Context, userID int64) (Records, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return Records{}, f.fail
	}
	r, ok := f.records[userID]
	if !ok {
		return Records{SMB: true}, nil
	}
	return Records{Profiles: slices.Clone(r.Profiles), JumpHosts: slices.Clone(r.JumpHosts),
		SOCKSProxies: slices.Clone(r.SOCKSProxies), SMBShares: slices.Clone(r.SMBShares), SMB: r.SMB}, nil
}

func (f *fakeStores) set(userID int64, r Records) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.records == nil {
		f.records = map[int64]*Records{}
	}
	f.records[userID] = &r
}

// CreateResource makes fakeStores a ResourceWriter. It stores the record in
// memory, runs within in a write transaction of db and drops the record
// again when within fails, as the real stores roll back.
func (f *fakeStores) CreateResource(ctx context.Context, userID int64, kind ResourceKind, payload jsontext.Value, within Within) (jsontext.Value, error) {
	f.mu.Lock()
	if f.refuse != nil {
		f.mu.Unlock()
		return nil, f.refuse
	}
	if f.records == nil {
		f.records = map[int64]*Records{}
	}
	r := f.records[userID]
	if r == nil {
		r = &Records{SMB: true}
		f.records[userID] = r
	}
	f.created++
	members, _ := pyjson.Members(payload)
	id := "new" + string(rune('0'+f.created))
	stored := pyjson.Object(append([]pyjson.Member{{Name: "id", Value: pyjson.String(id)}}, members...))
	list := map[ResourceKind]*[]jsontext.Value{ResourceSSH: &r.Profiles, ResourceJump: &r.JumpHosts,
		ResourceSOCKS: &r.SOCKSProxies, ResourceSMB: &r.SMBShares}[kind]
	*list = append(*list, stored)
	snapshot := Records{Profiles: slices.Clone(r.Profiles), JumpHosts: slices.Clone(r.JumpHosts),
		SOCKSProxies: slices.Clone(r.SOCKSProxies), SMBShares: slices.Clone(r.SMBShares), SMB: r.SMB}
	f.mu.Unlock()
	err := f.db.Write(ctx, func(tx *store.Tx) error { return within(ctx, tx, stored, snapshot) })
	if err != nil {
		f.mu.Lock()
		defer f.mu.Unlock()
		*list = slices.DeleteFunc(*list, func(v jsontext.Value) bool { s, _ := stringMember(v, "id"); return s == id })
		f.rolledBack++
		return nil, err
	}
	return stored, nil
}

// UpdateResource replaces the record id with the payload, runs within in
// a write transaction of db and puts the old record back when within
// fails.
func (f *fakeStores) UpdateResource(ctx context.Context, userID int64, kind ResourceKind, id string, payload jsontext.Value, within Within) (jsontext.Value, error) {
	f.mu.Lock()
	if f.refuse != nil {
		f.mu.Unlock()
		return nil, f.refuse
	}
	r := f.records[userID]
	if r == nil {
		f.mu.Unlock()
		return nil, fault.New(fault.NotFound, "")
	}
	list := map[ResourceKind]*[]jsontext.Value{ResourceSSH: &r.Profiles, ResourceJump: &r.JumpHosts,
		ResourceSOCKS: &r.SOCKSProxies, ResourceSMB: &r.SMBShares}[kind]
	i := slices.IndexFunc(*list, func(v jsontext.Value) bool { s, _ := stringMember(v, "id"); return s == id })
	if i < 0 {
		f.mu.Unlock()
		return nil, fault.New(fault.NotFound, "")
	}
	old := (*list)[i]
	members, _ := pyjson.Members(payload)
	members = pyjson.Delete(members, "id")
	stored := pyjson.Object(append([]pyjson.Member{{Name: "id", Value: pyjson.String(id)}}, members...))
	(*list)[i] = stored
	f.updated++
	snapshot := Records{Profiles: slices.Clone(r.Profiles), JumpHosts: slices.Clone(r.JumpHosts),
		SOCKSProxies: slices.Clone(r.SOCKSProxies), SMBShares: slices.Clone(r.SMBShares), SMB: r.SMB}
	f.mu.Unlock()
	if err := f.db.Write(ctx, func(tx *store.Tx) error { return within(ctx, tx, stored, snapshot) }); err != nil {
		f.mu.Lock()
		defer f.mu.Unlock()
		(*list)[i] = old
		f.rolledBack++
		return nil, err
	}
	return stored, nil
}

type fakePolicy struct {
	mu       sync.Mutex
	disabled bool
	revision string
}

func (f *fakePolicy) CredentialsPolicy(context.Context) (bool, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return !f.disabled, f.revision, nil
}

func (f *fakePolicy) set(enabled bool, revision string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.disabled, f.revision = !enabled, revision
}

type fakeAccounts map[int64]string

func (f fakeAccounts) Incarnation(_ context.Context, userID int64) (string, error) {
	if v, ok := f[userID]; ok {
		return v, nil
	}
	return "", errors.New("no such account")
}

type fakeAudit struct {
	mu      sync.Mutex
	actions []string
}

func (f *fakeAudit) CredentialChanged(_ context.Context, _ int64, action string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.actions = append(f.actions, action)
}

type credRig struct {
	*rig
	stores *fakeStores
	policy *fakePolicy
	audit  *fakeAudit
}

func newCredRig(t testing.TB) *credRig {
	t.Helper()
	r := &credRig{rig: newRig(t, Limits{}), stores: &fakeStores{}, policy: &fakePolicy{revision: "rev1"}, audit: &fakeAudit{}}
	r.stores.db = r.db
	if err := r.svc.EnableCredentials(CredentialOptions{Stores: r.stores, Writer: r.stores, Policy: r.policy,
		Accounts: fakeAccounts{7: "2026-11-20T08:15:30.123456", 1: "2026-01-01T00:00:00"}, Audit: r.audit}); err != nil {
		t.Fatal(err)
	}
	return r
}

func obj(t testing.TB, v any) jsontext.Value {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return jsontext.Value(b)
}

// do prepares and applies a mutation as the page does, without a grant.
func (r *credRig) do(t testing.TB, p principal.Principal, method, rid string, payload map[string]any) (jsontext.Value, error) {
	t.Helper()
	return r.doGrant(t, p, method, rid, payload, "")
}

func (r *credRig) doGrant(t testing.TB, p principal.Principal, method, rid string, payload map[string]any, grant string) (jsontext.Value, error) {
	t.Helper()
	token, err := r.prepare(t, p, method, rid, payload)
	if err != nil {
		return nil, err
	}
	body := map[string]any{"intent": token}
	maps.Copy(body, payload)
	if grant == "issue" {
		grant = r.grant(p, principal.ActionCredentialsVault, token)
	}
	return r.svc.Apply(as(p), method, rid, obj(t, body), grant)
}

func (r *credRig) prepare(t testing.TB, p principal.Principal, method, rid string, payload map[string]any) (string, error) {
	t.Helper()
	mutation := map[string]any{"method": method}
	maps.Copy(mutation, payload)
	if rid != "" {
		mutation["credential_id"] = rid
	}
	out, err := r.svc.Prepare(as(p), obj(t, map[string]any{"operation": "native", "mutation": mutation}))
	if err != nil {
		return "", err
	}
	tok, _ := stringMember(out, "intent")
	return tok, nil
}

func codeOf(err error) fault.Code {
	if err == nil {
		return ""
	}
	e, ok := fault.From(err)
	if !ok {
		return "untyped"
	}
	return e.Code
}

type stateView struct {
	Enabled     bool `json:"enabled"`
	LegacyVault bool `json:"legacy_vault"`
	Credentials []struct {
		ID       string `json:"id"`
		Name     string `json:"name"`
		Username string `json:"username"`
		Version  string `json:"version"`
		Uses     []struct {
			ResourceID string `json:"resource_id"`
			Valid      bool   `json:"valid"`
			Name       string `json:"name"`
		} `json:"uses"`
	} `json:"credentials"`
	Profiles []struct {
		ID         string  `json:"id"`
		Kind       string  `json:"kind"`
		CredID     *string `json:"credential_id"`
		Status     string  `json:"credential_status"`
		Assignment *struct {
			CredentialID string `json:"credential_id"`
			Fingerprint  string `json:"fingerprint"`
			Generation   string `json:"generation"`
		} `json:"credential_assignment"`
	} `json:"profiles"`
}

func (r *credRig) state(t testing.TB, p principal.Principal) stateView {
	t.Helper()
	raw, err := r.svc.State(as(p))
	if err != nil {
		t.Fatal(err)
	}
	var v stateView
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func (v stateView) profile(id string) (status string, cred string) {
	for _, p := range v.Profiles {
		if p.ID == id {
			if p.CredID != nil {
				cred = *p.CredID
			}
			return p.Status, cred
		}
	}
	return "", ""
}

func (v stateView) credential(name string) string {
	for _, c := range v.Credentials {
		if c.Name == name {
			return c.ID
		}
	}
	return ""
}
