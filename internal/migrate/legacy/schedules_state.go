package legacy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"errors"
	"maps"
	"slices"

	"golang.org/x/crypto/ssh"

	"github.com/bifrost0x/webssh/internal/automation"
	"github.com/bifrost0x/webssh/internal/pyjson"
	"github.com/bifrost0x/webssh/internal/vault"
)

// scheduleUser is an account as the schedule validation reads it.
type scheduleUser struct {
	incarnation    string
	noIncarnation  bool
	authGeneration int64
	locked         bool
}

// legacyState is the legacy state a grant is validated against, read
// lazily per account.
type legacyState struct {
	users              map[int64]scheduleUser
	automationRevision string
	credentialsOn      bool
	credentialsRev     string
	hosts              map[int64]vault.Records
}

func newLegacyState(ctx context.Context, src *Source) (*legacyState, error) {
	st := &legacyState{users: map[int64]scheduleUser{}, hosts: map[int64]vault.Records{}}
	rows, err := src.AccountRows(ctx)
	if err != nil {
		return nil, err
	}
	for _, a := range rows {
		u := scheduleUser{authGeneration: a.AuthGeneration, locked: a.IsLocked}
		if u.incarnation, err = a.Incarnation(); err != nil {
			u.noIncarnation = true
		}
		st.users[a.ID] = u
	}
	app, err := src.AppSettings()
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	if err == nil {
		st.automationRevision = memberText(app.Raw, "automation_enabled_revision")
		on, _ := pyjson.Get(app.Raw, "credentials_enabled")
		st.credentialsOn = on.Kind() == 't'
		st.credentialsRev = memberText(app.Raw, "credentials_enabled_revision")
	}
	users, err := readUserHosts(ctx, src)
	if err != nil {
		return nil, err
	}
	for _, h := range users {
		st.hosts[h.id] = vault.Records{Profiles: h.legacy.Profiles, JumpHosts: h.legacy.JumpHosts, SOCKSProxies: h.legacy.SOCKSProxies}
	}
	return st, nil
}

func memberText(v jsontext.Value, name string) string {
	m, _ := pyjson.Get(v, name)
	s, _ := textOf(m)
	return s
}

// validGrant is _validate_snapshot of app/automation_schedule.py against
// the legacy state; reason names the first rule that failed.
func (st *legacyState) validGrant(ctx context.Context, src *Source, userID int64, epoch string, g legacyGrant) (bool, string) {
	u := st.users[userID]
	switch {
	case u.noIncarnation:
		return false, "account_without_incarnation"
	case u.locked:
		return false, "account_locked"
	}
	want := automation.AccountTuple(automation.AccountBinding{Incarnation: u.incarnation, AuthGeneration: u.authGeneration, Epoch: epoch})
	if !automation.SameJSON(pyjson.Array(g.Account), want) {
		return false, "account_changed"
	}
	if g.Policy != st.automationRevision {
		return false, "policy_changed"
	}
	books, err := legacyRunbooks(src, userID)
	if err != nil || !slices.ContainsFunc(books, func(b jsontext.Value) bool { return automation.SameJSON(b, g.Book) }) {
		return false, "runbook_changed"
	}
	resources := vault.ResourcesFromRecords(st.hosts[userID])
	current := map[string]jsontext.Value{}
	for _, r := range resources {
		if r.Kind == vault.ResourceSSH {
			current[r.ID] = pyjson.Object(r.Page)
		}
	}
	for _, t := range g.Targets {
		cur, ok := current[memberText(t, "id")]
		if !ok {
			cur = jsontext.Value("{}")
		}
		a, okA := vault.RecordFingerprint(cur)
		b, okB := vault.RecordFingerprint(t)
		if !okA || !okB || a != b {
			return false, "target_changed"
		}
	}
	digests, ok := st.keyDigests(src, userID, g.Targets)
	if !ok || !maps.Equal(digests, g.KeyDigests) {
		return false, "key_changed"
	}
	hops := passwordHopsOf(g.Targets)
	if len(hops) == 0 {
		return true, ""
	}
	binding, ok := st.binding(ctx, src, userID, resources, hops)
	if !ok || !automation.SameJSON(binding, g.Binding) {
		return false, "saved_password_changed"
	}
	return true, ""
}

func legacyRunbooks(src *Source, userID int64) ([]jsontext.Value, error) {
	doc, found, err := userStore(src, userID, "automation")
	if err != nil || !found {
		return nil, err
	}
	return doc.RawList("runbooks")
}

// connectionHops is connection_resources: each target's route, then the
// target, each id once.
func connectionHops(targets []jsontext.Value) []jsontext.Value {
	seen := map[string]bool{}
	var out []jsontext.Value
	for _, t := range targets {
		route, _ := pyjson.Get(t, "route")
		for _, item := range []jsontext.Value{route, t} {
			if item.Kind() != '{' {
				continue
			}
			if id := memberText(item, "id"); !seen[id] {
				seen[id] = true
				out = append(out, item)
			}
		}
	}
	return out
}

func passwordHopsOf(targets []jsontext.Value) []jsontext.Value {
	var out []jsontext.Value
	for _, h := range connectionHops(targets) {
		if memberText(h, "auth_type") == "password" {
			out = append(out, h)
		}
	}
	return out
}

// keyDigests is _key_digests: the digest of every key hop's decrypted key.
func (st *legacyState) keyDigests(src *Source, userID int64, targets []jsontext.Value) (map[string]string, bool) {
	keys, err := src.SSHKeys(userID)
	if err != nil {
		return nil, false
	}
	out := map[string]string{}
	for _, h := range connectionHops(targets) {
		if memberText(h, "auth_type") != "key" {
			continue
		}
		id := memberText(h, "key_id")
		i := slices.IndexFunc(keys.Keys, func(k SSHKey) bool { return k.ID == id })
		if id == "" || i < 0 || len(keys.Keys[i].PEM) == 0 {
			return nil, false
		}
		out[memberText(h, "id")] = keyDigest(keys.Keys[i].PEM)
	}
	return out, true
}

// publicKeyDigests is the digest the run side of internal/automation
// binds a key with: SHA-256 of the public key in SSH wire form, for every
// key hop of the targets.
func (st *legacyState) publicKeyDigests(src *Source, userID int64, targets []jsontext.Value) (map[string]string, bool) {
	keys, err := src.SSHKeys(userID)
	if err != nil {
		return nil, false
	}
	out := map[string]string{}
	for _, h := range connectionHops(targets) {
		if memberText(h, "auth_type") != "key" {
			continue
		}
		id := memberText(h, "key_id")
		i := slices.IndexFunc(keys.Keys, func(k SSHKey) bool { return k.ID == id })
		if id == "" || i < 0 {
			return nil, false
		}
		signer, err := ssh.ParsePrivateKey(keys.Keys[i].PEM)
		if err != nil {
			return nil, false
		}
		sum := sha256.Sum256(signer.PublicKey().Marshal())
		out[memberText(h, "id")] = hex.EncodeToString(sum[:])
	}
	return out, true
}

// binding is schedule_generations against the legacy saved passwords.
func (st *legacyState) binding(ctx context.Context, src *Source, userID int64, resources []vault.Resource, hops []jsontext.Value) (jsontext.Value, bool) {
	if !st.credentialsOn {
		return nil, false
	}
	creds, refs, err := src.NamedCredentials(ctx, userID)
	if err != nil {
		return nil, false
	}
	records := map[string][2]string{}
	for _, h := range hops {
		id := memberText(h, "id")
		var matches []vault.Resource
		for _, r := range resources {
			if r.ID == id {
				matches = append(matches, r)
			}
		}
		want, ok := vault.RecordFingerprint(h)
		if len(matches) != 1 || !ok {
			return nil, false
		}
		cur, okC := vault.RecordFingerprint(pyjson.Object(matches[0].Page))
		ref, assigned := refs[id]
		if !okC || cur != want || !assigned || ref.Fingerprint != want {
			return nil, false
		}
		i := slices.IndexFunc(creds, func(c NamedCredential) bool { return c.ID == ref.CredentialID })
		if i < 0 {
			return nil, false
		}
		records[id] = [2]string{ref.Generation, creds[i].Version}
	}
	u := st.users[userID]
	return vault.ScheduleBinding(u.incarnation, st.credentialsRev, records), true
}
