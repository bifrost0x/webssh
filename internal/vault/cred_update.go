package vault

import (
	"context"
	"encoding/json/jsontext"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/pyjson"
	"github.com/bifrost0x/webssh/internal/store"
)

// resourceFields are the payload members passed on to the store of a jump
// host and a SOCKS proxy (add_jump_host, add_socks_proxy); the optional
// ones only when the page sent them. Saved hosts get the payload.
var resourceFields = map[ResourceKind]struct{ always, optional []string }{
	ResourceJump:  {always: []string{"name", "host", "port", "username", "auth_type", "key_id", "jump_host_id"}, optional: []string{"legacy_algorithms"}},
	ResourceSOCKS: {always: []string{"name", "host", "port", "username", "auth_type"}},
}

func resourcePayload(kind ResourceKind, payload jsontext.Value) jsontext.Value {
	fields, ok := resourceFields[kind]
	if !ok {
		return payload
	}
	var members []pyjson.Member
	for _, n := range fields.always {
		v, _ := field(payload, n)
		members = append(members, pyjson.Member{Name: n, Value: v})
	}
	for _, n := range fields.optional {
		if v, present := field(payload, n); present {
			members = append(members, pyjson.Member{Name: n, Value: v})
		}
	}
	if kind == ResourceSOCKS {
		dns, present := field(payload, "remote_dns")
		if !present {
			dns = jsonTrue
		}
		members = append(members, pyjson.Member{Name: "remote_dns", Value: dns})
	}
	return pyjson.Object(members)
}

// withResource reports an assign or create of a saved resource that also
// carries the edited resource (new in 3.4).
func withResource(body jsontext.Value) bool {
	v, ok := field(body, "resource")
	return ok && v.Kind() != 'n'
}

// applyWithResource saves an edited resource and its password assignment
// in one transaction (T4): the change of the record and of the assignment
// both happen, or neither does. The intent was prepared against the
// resource as it was; the assignment is checked against the record as
// the transaction stores it. Binding a saved password needed the step-up
// before this runs (Apply).
func (s *Service) applyWithResource(ctx context.Context, c *credentials, p principal.Principal, revision, token string, mutation jsontext.Value) ([]pyjson.Member, error) {
	if _, _, err := c.policy(ctx, false); err != nil {
		return nil, err
	}
	in, err := c.intents.lookup(p, revision, token, false)
	if err != nil {
		return nil, err
	}
	resID, _ := field(mutation, "resource_id")
	all, _, err := c.resources(ctx, p.UserID)
	if err != nil {
		return nil, err
	}
	var matches []Resource
	for _, r := range all {
		if sameJSON(pyjson.String(r.ID), resID) {
			matches = append(matches, r)
		}
	}
	if !in.hasResource || len(matches) != 1 || matches[0].Fingerprint != in.frozen {
		return nil, fault.New(fault.PreviewChanged, "")
	}
	r := matches[0]
	kind, recordID, err := ParseResourceID(r.ID)
	if err != nil {
		return nil, err
	}
	payload, _ := field(mutation, "resource")
	id, hasID := field(payload, "id")
	if payload.Kind() != '{' || kind == ResourceSMB || (hasID && id.Kind() != 'n' && !sameJSON(id, pyjson.String(recordID))) {
		return nil, fault.New(fault.InvalidRequest, "")
	}
	if c.Writer == nil {
		return nil, fault.New(fault.NotAvailableInPreview, "")
	}
	if _, err := c.intents.lookup(p, revision, token, true); err != nil {
		return nil, err
	}
	var assignErr error
	stored, err := c.Writer.UpdateResource(ctx, p.UserID, kind, recordID, resourcePayload(kind, payload),
		func(ctx context.Context, tx *store.Tx, _ jsontext.Value, records Records) error {
			assignErr = s.assignEdited(ctx, tx, p, r.ID, records, mutation, in.prior)
			return assignErr
		})
	switch {
	case assignErr != nil:
		return nil, assignErr
	case fault.Is(err, fault.DuplicateName), fault.Is(err, fault.ValidationError), fault.Is(err, fault.NotFound):
		return nil, err
	case err != nil:
		return nil, fault.New(fault.InvalidTargets, "")
	}
	return []pyjson.Member{{Name: "resource", Value: stored}}, nil
}

// assignEdited applies the assignment to the resource as the transaction
// stores it after the edit; a target the page names must be that record's.
func (s *Service) assignEdited(ctx context.Context, tx *store.Tx, p principal.Principal, resourceID string, records Records, mutation jsontext.Value, prior *Assignment) error {
	r, err := resolve(ResourcesFromRecords(records), resourceID)
	if err != nil {
		return err
	}
	if target, _ := field(mutation, "target"); target.Kind() != 'n' {
		want, err := normalizeTarget(target)
		if err != nil {
			return err
		}
		have, err := normalizeTarget(pyjson.Object(r.Page))
		if err != nil || want != have {
			return fault.New(fault.CredentialTargetChanged, "")
		}
	}
	d, err := loadDoc(ctx, tx, p.UserID)
	if err != nil {
		return storage(err)
	}
	if err := s.assignTo(p, d, r, mutation, prior); err != nil {
		return err
	}
	if err := saveDoc(ctx, tx, p.UserID, d); err != nil {
		return storage(err)
	}
	return nil
}
