package vault

import (
	"context"
	"encoding/json/jsontext"
	"slices"
	"strings"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/pyjson"
	"github.com/bifrost0x/webssh/internal/store"
)

// status is credential_status: the state of a resource's assignment.
func status(enabled bool, d *credDoc, r Resource) Status {
	if !enabled {
		return StatusDisabled
	}
	a, ok := d.assignment(r.ID)
	if !ok {
		return StatusMissing
	}
	if r.Fingerprint == "" || a.Fingerprint != r.Fingerprint {
		return StatusChanged
	}
	if _, ok := d.record(a.CredentialID); !ok {
		return StatusMissing
	}
	return StatusReady
}

func assignmentJSON(a *Assignment) jsontext.Value {
	if a == nil {
		return jsonNull
	}
	return pyjson.Object([]pyjson.Member{
		{Name: "credential_id", Value: pyjson.String(a.CredentialID)},
		{Name: "fingerprint", Value: pyjson.String(a.Fingerprint)},
		{Name: "generation", Value: pyjson.String(a.Generation)},
	})
}

func publicCredential(c *credRow, uses jsontext.Value) jsontext.Value {
	return pyjson.Object([]pyjson.Member{
		{Name: "id", Value: pyjson.String(c.ID)}, {Name: "name", Value: pyjson.String(c.Name)},
		{Name: "username", Value: pyjson.String(c.Username)}, {Name: "version", Value: pyjson.String(c.Version)},
		{Name: "updated_at", Value: pyjson.String(c.UpdatedAt)}, {Name: "uses", Value: uses},
	})
}

// legacyRevision is digest() of the legacy vault document as the Python
// release recorded it in imports: SHA-256 of the sorted, compact JSON.
// The members are base64 text and the version, so ensure_ascii changes
// nothing.
func legacyRevision(v legacyVault) (string, bool) {
	doc, _, err := pyjson.Load(v.Document)
	if err != nil {
		return "", false
	}
	return pythonDigest(doc)
}

// State is the credentials page's view of the signed-in user
// (native_state): the passwords with their live uses, every resource with
// its assignment and status, and whether a legacy vault waits for import.
func (s *Service) State(ctx context.Context) (jsontext.Value, error) {
	p, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	c, err := s.credentials()
	if err != nil {
		return nil, err
	}
	enabled, _, err := c.policy(ctx, true)
	if err != nil {
		return nil, err
	}
	all, _, err := c.resources(ctx, p.UserID)
	if err != nil {
		return nil, err
	}
	var d *credDoc
	var legacy legacyVault
	var hasLegacy bool
	err = s.db.Read(ctx, func(tx *store.Tx) error {
		var err error
		if d, err = loadDoc(ctx, tx, p.UserID); err != nil {
			return err
		}
		legacy, hasLegacy, err = loadLegacyVault(ctx, tx, p.UserID)
		return err
	})
	if err != nil {
		return nil, storage(err)
	}
	profiles := make([]jsontext.Value, 0, len(all))
	for _, r := range all {
		members := slices.Clone(r.Page)
		a, ok := d.assignment(r.ID)
		credID := jsonNull
		if !ok {
			a = nil
		} else {
			credID = pyjson.String(a.CredentialID)
		}
		members = pyjson.Set(members, "credential_id", credID)
		members = pyjson.Set(members, "credential_assignment", assignmentJSON(a))
		members = pyjson.Set(members, "credential_status", pyjson.String(string(status(enabled, d, r))))
		profiles = append(profiles, pyjson.Object(members))
	}
	creds := make([]jsontext.Value, 0, len(d.creds))
	for i := range d.creds {
		rec := &d.creds[i]
		var uses []jsontext.Value
		for _, rid := range d.uses(rec.ID) {
			i := slices.IndexFunc(all, func(r Resource) bool { return r.ID == rid })
			if i < 0 {
				continue // a deleted resource is no longer a use
			}
			a, _ := d.assignment(rid)
			valid := slices.ContainsFunc(all, func(r Resource) bool { return r.ID == rid && r.Fingerprint != "" && r.Fingerprint == a.Fingerprint })
			name := all[i].Name
			if name.Kind() == 'n' && !hasMember(all[i].Page, "name") {
				name = pyjson.String(rid)
			}
			uses = append(uses, pyjson.Object([]pyjson.Member{
				{Name: "resource_id", Value: pyjson.String(rid)}, {Name: "id", Value: pyjson.String(rid)},
				{Name: "name", Value: name}, {Name: "kind", Value: pyjson.String(string(all[i].Kind))},
				{Name: "valid", Value: boolJSON(valid)},
			}))
		}
		creds = append(creds, publicCredential(rec, pyjson.Array(uses)))
	}
	waiting := false
	if hasLegacy {
		rev, ok := legacyRevision(legacy)
		waiting = !ok || !slices.Contains(d.imports, rev)
	}
	vault := pyjson.Object([]pyjson.Member{
		{Name: "exists", Value: boolJSON(hasLegacy)}, {Name: "unlocked", Value: jsontext.Value("false")},
		{Name: "expires_in", Value: jsontext.Value("0")}, {Name: "credentials", Value: jsontext.Value("[]")},
	})
	return pyjson.Object([]pyjson.Member{
		{Name: "enabled", Value: boolJSON(enabled)}, {Name: "credentials", Value: pyjson.Array(creds)},
		{Name: "profiles", Value: pyjson.Array(profiles)}, {Name: "legacy_vault", Value: boolJSON(waiting)},
		{Name: "vault", Value: vault},
		// New in 3.4: create_for_resource also takes a saved password, so
		// the page creates a resource and its assignment in one step.
		{Name: "assign_on_create", Value: jsonTrue},
	}), nil
}

func hasMember(members []pyjson.Member, name string) bool {
	return slices.ContainsFunc(members, func(m pyjson.Member) bool { return m.Name == name })
}

func boolJSON(b bool) jsontext.Value {
	if b {
		return jsonTrue
	}
	return jsontext.Value("false")
}

// field returns a member of a request object, null when absent.
func field(v jsontext.Value, name string) (jsontext.Value, bool) {
	m, ok := pyjson.Get(v, name)
	if !ok {
		return jsonNull, false
	}
	return m, true
}

// createNamed stores a new password from a request (create_named).
func (s *Service) createNamed(userID int64, d *credDoc, data jsontext.Value) (*credRow, error) {
	nameV, _ := field(data, "name")
	name, err := textValue(nameV, MaxNameBytes, false)
	if err != nil {
		return nil, err
	}
	username := ""
	if v, ok := field(data, "username"); ok {
		if username, err = textValue(v, MaxUsernameBytes, true); err != nil {
			return nil, err
		}
	}
	pwV, _ := field(data, "password")
	password, err := textValue(pwV, MaxSecretBytes, false)
	if err != nil {
		return nil, err
	}
	rec, err := s.newCredential(userID, name, username, []byte(password))
	if err != nil {
		return nil, err
	}
	d.creds = append(d.creds, rec)
	return &d.creds[len(d.creds)-1], nil
}

// record is NamedStore.record: a valid id of an existing password.
func record(d *credDoc, id jsontext.Value) (*credRow, error) {
	rid, err := textValue(id, 128, false)
	if err != nil {
		return nil, err
	}
	r, ok := d.record(rid)
	if !ok {
		return nil, fault.New(fault.NotFound, "")
	}
	return r, nil
}

// updateNamed changes the name, username or password of a record.
func (s *Service) updateNamed(userID int64, d *credDoc, rid string, data jsontext.Value) error {
	rec, err := record(d, pyjson.String(rid))
	if err != nil {
		return err
	}
	if v, ok := field(data, "name"); ok {
		if rec.Name, err = textValue(v, MaxNameBytes, false); err != nil {
			return err
		}
	}
	if v, ok := field(data, "username"); ok {
		if rec.Username, err = textValue(v, MaxUsernameBytes, true); err != nil {
			return err
		}
	}
	if v, ok := field(data, "password"); ok {
		password, err := textValue(v, MaxSecretBytes, false)
		if err != nil {
			return err
		}
		sealed, err := s.sealSecret(userID, rec.ID, []byte(password))
		if err != nil {
			return err
		}
		rec.Secret, rec.Version = sealed, randomHex(32)
	}
	rec.UpdatedAt = pyISOTime(s.now())
	return nil
}

// deleteNamed removes a password. While saved passwords are on, a
// password assigned to a live resource is credential_in_use; assignments
// of deleted resources, or any while they are off, go with it.
func deleteNamed(d *credDoc, rid string, enabled bool, all []Resource, smbKnown bool) error {
	if _, err := record(d, pyjson.String(rid)); err != nil {
		return err
	}
	uses := d.uses(rid)
	if enabled && slices.ContainsFunc(uses, func(id string) bool {
		return slices.ContainsFunc(all, func(r Resource) bool { return r.ID == id }) ||
			(!smbKnown && strings.HasPrefix(id, string(ResourceSMB)+":"))
	}) {
		return fault.New(fault.CredentialInUse, "")
	}
	for _, id := range uses {
		d.unassign(id)
	}
	d.creds = slices.DeleteFunc(d.creds, func(c credRow) bool { return c.ID == rid })
	return nil
}
