package vault

import (
	"context"
	"encoding/json/jsontext"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/pyjson"
	"github.com/bifrost0x/webssh/internal/store"
)

// ResourceWriter creates a resource together with its password (provided
// in cmd/webssh over internal/hosts and internal/files/smb).
// CreateResource validates the payload as the resource's own save does,
// stores the new record and runs within in the same transaction; an error
// of within stores nothing. It returns the stored record.
type ResourceWriter interface {
	CreateResource(ctx context.Context, userID int64, kind ResourceKind, payload jsontext.Value, within Within) (jsontext.Value, error)
}

// Within runs in the transaction that stores a new resource. stored is the
// new record; records are the user's resources as that transaction sees
// them, the new one included.
type Within func(ctx context.Context, tx *store.Tx, stored jsontext.Value, records Records) error

// createFields are the payload members create_for_resource passes on for a
// jump host and a SOCKS proxy; saved hosts and SMB shares get the payload.
var createFields = map[ResourceKind][]string{
	ResourceJump:  {"name", "host", "port", "username", "auth_type", "key_id", "jump_host_id"},
	ResourceSOCKS: {"name", "host", "port", "username", "auth_type"},
}

// createForResource saves a new resource and a password assigned to it
// (create_for_resource): a new password from name and password, or, new
// in 3.4, the saved password credential_id. Resource and assignment are
// stored in one transaction, so a failed assignment leaves no resource.
// Binding a saved password needs the step-up, which Apply checks before
// anything is written.
func (s *Service) createForResource(ctx context.Context, c *credentials, p principal.Principal, data jsontext.Value) ([]pyjson.Member, error) {
	if _, _, err := c.policy(ctx, false); err != nil {
		return nil, err
	}
	kindV, _ := field(data, "resource_kind")
	kindS, _ := asString(kindV)
	kind := ResourceKind(kindS)
	payload, _ := field(data, "resource")
	id, _ := field(payload, "id")
	switch kind {
	case ResourceSSH, ResourceJump, ResourceSOCKS, ResourceSMB:
	default:
		return nil, fault.New(fault.InvalidRequest, "")
	}
	if payload.Kind() != '{' || truthy(id) {
		return nil, fault.New(fault.InvalidRequest, "")
	}
	if confirm, _ := field(data, "confirm_target"); confirm.Kind() != 't' {
		return nil, fault.New(fault.ConfirmationRequired, "")
	}
	if auth, _ := field(payload, "auth_type"); kind != ResourceSMB && string(auth) != `"password"` {
		return nil, fault.New(fault.InvalidTargets, "")
	}
	if names, ok := createFields[kind]; ok {
		var members []pyjson.Member
		for _, n := range names {
			v, _ := field(payload, n)
			members = append(members, pyjson.Member{Name: n, Value: v})
		}
		if kind == ResourceSOCKS {
			dns, present := field(payload, "remote_dns")
			if !present {
				dns = jsonTrue
			}
			members = append(members, pyjson.Member{Name: "remote_dns", Value: dns})
		}
		payload = pyjson.Object(members)
	}
	existing, saved := field(data, "credential_id")
	if saved && existing.Kind() != 'n' {
		_, hasName := field(data, "name")
		_, hasPassword := field(data, "password")
		if hasName || hasPassword {
			return nil, fault.New(fault.InvalidRequest, "")
		}
	} else {
		saved = false
	}
	if c.Writer == nil {
		return nil, fault.New(fault.NotAvailableInPreview, "")
	}
	var credential jsontext.Value
	var assignErr error
	stored, err := c.Writer.CreateResource(ctx, p.UserID, kind, payload, func(ctx context.Context, tx *store.Tx, stored jsontext.Value, records Records) error {
		assignErr = s.assignNew(ctx, tx, p, kind, stored, records, data, saved, &credential)
		return assignErr
	})
	switch {
	case assignErr != nil:
		return nil, assignErr
	case fault.Is(err, fault.DuplicateName):
		return nil, err
	case err != nil:
		return nil, fault.New(fault.InvalidTargets, "")
	}
	return []pyjson.Member{{Name: "resource", Value: stored}, {Name: "credential", Value: credential}}, nil
}

// assignNew assigns a password to the resource just stored in tx: the
// saved password of data when saved is set, else a new one.
func (s *Service) assignNew(ctx context.Context, tx *store.Tx, p principal.Principal, kind ResourceKind, stored jsontext.Value, records Records, data jsontext.Value, saved bool, credential *jsontext.Value) error {
	recordID, ok := stringMember(stored, "id")
	if !ok {
		return fault.New(fault.InvalidTargets, "")
	}
	r, err := resolve(ResourcesFromRecords(records), ResourceID(kind, recordID))
	if err != nil {
		return err
	}
	d, err := loadDoc(ctx, tx, p.UserID)
	if err != nil {
		return storage(err)
	}
	var rec *credRow
	if saved {
		id, _ := field(data, "credential_id")
		rec, err = record(d, id)
	} else {
		rec, err = s.createNamed(p.UserID, d, data)
	}
	if err != nil {
		return err
	}
	*credential = publicCredential(rec, jsontext.Value("[]"))
	d.assign(Assignment{ResourceID: r.ID, CredentialID: rec.ID, Fingerprint: r.Fingerprint, Generation: randomHex(32)})
	if err := saveDoc(ctx, tx, p.UserID, d); err != nil {
		return storage(err)
	}
	return nil
}

// liveRoute returns the fingerprint of the saved route of a normalized
// target, "" without one (_target_route): the typed SOCKS proxy, or the
// untyped jump host record as a saved host binds it.
func liveRoute(all []Resource, normalized jsontext.Value) (string, error) {
	if socks, _ := field(normalized, "socks_proxy_id"); truthy(socks) {
		id, _ := asString(socks)
		r, err := resolve(all, ResourceID(ResourceSOCKS, id))
		if err != nil {
			return "", err
		}
		return r.Fingerprint, nil
	}
	if jump, _ := field(normalized, "jump_host_id"); truthy(jump) {
		id, _ := asString(jump)
		r, err := resolve(all, ResourceID(ResourceJump, id))
		if err != nil {
			return "", err
		}
		members := pyjson.Delete(pyjson.Set(r.Page, "id", pyjson.String(id)), "kind")
		return rawFingerprint(pyjson.Object(members)), nil
	}
	return "", nil
}

// authorizeTarget lets one saved password be sent to a one-off target the
// user confirmed (Quick Connect without a saved host). The token it
// returns is valid for IntentTTL in this session, for exactly this target,
// password version and route.
func (s *Service) authorizeTarget(ctx context.Context, c *credentials, p principal.Principal, data jsontext.Value) (jsontext.Value, error) {
	_, revision, err := c.policy(ctx, false)
	if err != nil {
		return nil, err
	}
	target, _ := field(data, "target")
	if confirm, _ := field(data, "confirm_target"); confirm.Kind() != 't' || target.Kind() != '{' {
		return nil, fault.New(fault.ConfirmationRequired, "")
	}
	normalized, err := normalizeTarget(target)
	if err != nil {
		return nil, err
	}
	host, _ := field(jsontext.Value(normalized), "host")
	user, _ := field(jsontext.Value(normalized), "username")
	if _, err := textValue(host, 253, false); err != nil {
		return nil, err
	}
	if _, err := textValue(user, 256, false); err != nil {
		return nil, err
	}
	if auth, _ := field(jsontext.Value(normalized), "auth_type"); string(auth) != `"password"` {
		return nil, fault.New(fault.InvalidTargets, "")
	}
	d, err := s.readDoc(ctx, p.UserID)
	if err != nil {
		return nil, err
	}
	credID, _ := field(data, "credential_id")
	rec, err := record(d, credID)
	if err != nil {
		return nil, err
	}
	all, _, err := c.resources(ctx, p.UserID)
	if err != nil {
		return nil, err
	}
	route, err := liveRoute(all, jsontext.Value(normalized))
	if err != nil {
		return nil, err
	}
	token, err := c.intents.remember(p, revision, intent{kind: intentTarget, target: normalized, credentialID: rec.ID, version: rec.Version, route: route})
	if err != nil {
		return nil, err
	}
	return pyjson.Object([]pyjson.Member{{Name: "credential_target_token", Value: pyjson.String(token)}}), nil
}

// TargetPassword returns the password a target token authorized for the
// connection target t (target_password). The token stays valid until it
// expires, so a reconnect within IntentTTL needs no new confirmation. Any
// difference of target, password version, route or policy fails.
func (s *Service) TargetPassword(ctx context.Context, p principal.Principal, credentialID, token string, t Target) ([]byte, error) {
	c, err := s.credentials()
	if err != nil {
		return nil, err
	}
	_, revision, err := c.policy(ctx, false)
	if err != nil {
		return nil, err
	}
	in, err := c.intents.lookup(p, revision, token, false)
	if err != nil {
		return nil, err
	}
	if in.kind != intentTarget || in.credentialID != credentialID {
		return nil, fault.New(fault.InvalidIntent, "")
	}
	connection, err := normalizeTarget(targetJSON(t))
	if err != nil || connection != in.target {
		return nil, fault.New(fault.CredentialTargetChanged, "")
	}
	d, err := s.readDoc(ctx, p.UserID)
	if err != nil {
		return nil, err
	}
	rec, err := record(d, pyjson.String(credentialID))
	if err != nil {
		return nil, err
	}
	if rec.Version != in.version {
		return nil, fault.New(fault.CredentialTargetChanged, "")
	}
	all, _, err := c.resources(ctx, p.UserID)
	if err != nil {
		return nil, err
	}
	if route, err := liveRoute(all, jsontext.Value(in.target)); err != nil || route != in.route {
		return nil, fault.New(fault.CredentialTargetChanged, "")
	}
	return s.open(p.UserID, rec)
}

// Password returns the saved password assigned to a resource of the user
// (schedule_password). t is the target the caller is about to connect
// to; it must be the resource as it is now and as it was when the user
// assigned the password. The secret is a fresh copy for the caller to
// clear; it is never logged.
func (s *Service) Password(ctx context.Context, userID int64, resourceID string, t Target) ([]byte, error) {
	c, err := s.credentials()
	if err != nil {
		return nil, err
	}
	if _, _, err := c.policy(ctx, false); err != nil {
		return nil, err
	}
	all, _, err := c.resources(ctx, userID)
	if err != nil {
		return nil, err
	}
	current, err := resolve(all, resourceID)
	if err != nil {
		return nil, err
	}
	want := Fingerprint(t)
	if !current.Password || current.Fingerprint == "" || current.Fingerprint != want {
		return nil, fault.New(fault.CredentialTargetChanged, "")
	}
	d, err := s.readDoc(ctx, userID)
	if err != nil {
		return nil, err
	}
	a, ok := d.assignment(resourceID)
	if !ok {
		return nil, fault.New(fault.CredentialMissing, "")
	}
	if a.Fingerprint != want {
		return nil, fault.New(fault.CredentialTargetChanged, "")
	}
	rec, ok := d.record(a.CredentialID)
	if !ok {
		return nil, fault.New(fault.CredentialMissing, "")
	}
	return s.open(userID, rec)
}
