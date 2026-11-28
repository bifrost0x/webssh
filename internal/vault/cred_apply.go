package vault

import (
	"context"
	"encoding/json/jsontext"
	"slices"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/pyjson"
	"github.com/bifrost0x/webssh/internal/store"
)

// Methods of the page's mutations (credential_routes.py _native).
const (
	MethodCreate            = "create"
	MethodUpdate            = "update"
	MethodDelete            = "delete"
	MethodAssign            = "assign"
	MethodImport            = "import"
	MethodAuthorizeTarget   = "authorize_target"
	MethodCreateForResource = "create_for_resource"
)

// Rate limits of preparing an intent: ordinary changes have their own
// budget; a legacy import tries a passphrase and gets the small one.
const (
	changeAttemptsPerMinute = 120
	importAttemptsPerMinute = 10
)

// Prepare is POST /api/credentials/intents: it checks a mutation the page
// is about to send and returns the intent token that binds it to the user,
// the session and its digest. Only the "native" operations exist; the
// passphrase vault operations are dropped (D-06).
func (s *Service) Prepare(ctx context.Context, data jsontext.Value) (jsontext.Value, error) {
	p, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	c, err := s.credentials()
	if err != nil {
		return nil, err
	}
	operation, _ := field(data, "operation")
	mutation, _ := field(data, "mutation")
	method, _ := asString(func() jsontext.Value { m, _ := field(mutation, "method"); return m }())
	bucket, limit := "credential_change", changeAttemptsPerMinute
	if method == MethodImport || string(operation) != `"native"` {
		bucket, limit = "legacy_vault", importAttemptsPerMinute
	}
	if !c.intents.allow(p.UserID, bucket, limit) {
		return nil, fault.New(fault.Busy, "")
	}
	_, revision, err := c.policy(ctx, method == MethodDelete)
	if err != nil {
		return nil, err
	}
	if string(operation) != `"native"` || mutation.Kind() != '{' {
		return nil, fault.New(fault.InvalidRequest, "")
	}
	in := intent{kind: intentNative}
	if resID, _ := field(mutation, "resource_id"); (method == MethodCreate || method == MethodAssign) && truthy(resID) {
		if err := s.freeze(ctx, c, p, mutation, resID, method, &in); err != nil {
			return nil, err
		}
	}
	digest, ok := digestOf(mutation)
	if !ok {
		return nil, fault.New(fault.InvalidRequest, "")
	}
	in.digest = digest
	token, err := c.intents.remember(p, revision, in)
	if err != nil {
		return nil, err
	}
	return pyjson.Object([]pyjson.Member{{Name: "intent", Value: pyjson.String(token)}, {Name: "expires_in", Value: jsontext.Value("300")}}), nil
}

// freeze records the target and the prior assignment an assignment is
// prepared against, and refuses a replacement the page did not confirm.
func (s *Service) freeze(ctx context.Context, c *credentials, p principal.Principal, mutation, resID jsontext.Value, method string, in *intent) error {
	id, err := textValue(resID, 128, false)
	if err != nil {
		return err
	}
	all, _, err := c.resources(ctx, p.UserID)
	if err != nil {
		return err
	}
	r, err := resolve(all, id)
	if err != nil {
		return err
	}
	d, err := s.readDoc(ctx, p.UserID)
	if err != nil {
		return err
	}
	in.frozen, in.assignsTo, in.hasResource = r.Fingerprint, r.ID, true
	prior, ok := d.assignment(r.ID)
	if ok {
		cp := *prior
		in.prior = &cp
	}
	if expected, present := field(mutation, "expected_assignment"); present && !sameJSON(expected, assignmentJSON(in.prior)) {
		return fault.New(fault.PreviewChanged, "")
	}
	credID, _ := field(mutation, "credential_id")
	replacing := in.prior != nil && (method == MethodCreate ||
		(credID.Kind() != 'n' && !sameJSON(credID, pyjson.String(in.prior.CredentialID))))
	if replace, _ := field(mutation, "replace_credential_id"); replacing && !sameJSON(replace, pyjson.String(in.prior.CredentialID)) {
		return fault.New(fault.ReplacementConfirmationRequired, "")
	}
	return nil
}

// bindsSavedSecret reports the mutations that let the server send an
// existing saved secret to a destination chosen in this request; they need
// a step-up, as reading the secret would. A new resource created with a
// saved password (new in 3.4) is one of them.
func bindsSavedSecret(method string, data jsontext.Value) bool {
	if method == MethodAssign || method == MethodCreateForResource {
		v, _ := field(data, "credential_id")
		return truthy(v)
	}
	return method == MethodImport || method == MethodAuthorizeTarget
}

// Apply runs a prepared mutation of the page (_native of
// credential_routes.py). rid is the credential id of PATCH and DELETE.
// grant is the step-up grant of the request, used when the mutation binds
// a saved secret and the session has no recent binding assurance. It
// returns the new page state, or the target token of authorize_target.
func (s *Service) Apply(ctx context.Context, method, rid string, data jsontext.Value, grant string) (jsontext.Value, error) {
	p, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	c, err := s.credentials()
	if err != nil {
		return nil, err
	}
	members, ok := pyjson.Members(data)
	if !ok {
		return nil, fault.New(fault.InvalidRequest, "")
	}
	tokenV, _ := field(data, "intent")
	token, _ := asString(tokenV)
	members = pyjson.Delete(members, "intent")
	body := pyjson.Object(members)
	if resID, _ := field(body, "resource_id"); method == MethodAssign && !truthy(resID) {
		return nil, fault.New(fault.InvalidTargets, "")
	}
	members = pyjson.Set(slices.Clone(members), "method", pyjson.String(method))
	if rid != "" {
		members = pyjson.Set(members, "credential_id", pyjson.String(rid))
	}
	mutation := pyjson.Object(members)
	enabled, revision, err := c.policy(ctx, true)
	if err != nil {
		return nil, err
	}
	in, err := c.intents.lookup(p, revision, token, false)
	digest, ok := digestOf(mutation)
	if err != nil || in.kind != intentNative || !ok || in.digest != digest {
		return nil, fault.New(fault.InvalidIntent, "")
	}
	if bindsSavedSecret(method, body) && !c.intents.assured(p, revision) {
		// Checked before the intent is consumed, so the page can complete
		// the step-up for this exact intent and send it again.
		if err := s.stepUp.Consume(ctx, p, principal.ActionCredentialsVault, token, grant); err != nil {
			return nil, err
		}
		c.intents.assure(p, revision)
	}
	resID, _ := field(body, "resource_id")
	var result []pyjson.Member
	switch {
	case method == MethodAuthorizeTarget:
		if _, err := c.intents.lookup(p, revision, token, true); err != nil {
			return nil, err
		}
		out, err := s.authorizeTarget(ctx, c, p, body)
		if err == nil {
			c.audit(ctx, p.UserID, method)
		}
		return out, err
	case (method == MethodCreate || method == MethodAssign) && truthy(resID):
		err = s.applyAssignment(ctx, c, p, revision, token, mutation)
	default:
		if _, err := c.intents.lookup(p, revision, token, true); err != nil {
			return nil, err
		}
		result, err = s.applyNamed(ctx, c, p, method, rid, body, enabled)
	}
	if err != nil {
		return nil, err
	}
	c.audit(ctx, p.UserID, method)
	state, err := s.State(ctx)
	if err != nil {
		return nil, err
	}
	out, _ := pyjson.Members(state)
	for _, m := range result {
		out = pyjson.Set(out, m.Name, m.Value)
	}
	return pyjson.Object(out), nil
}

func (s *Service) applyNamed(ctx context.Context, c *credentials, p principal.Principal, method, rid string, body jsontext.Value, enabled bool) ([]pyjson.Member, error) {
	switch method {
	case MethodCreateForResource:
		return s.createForResource(ctx, c, p, body)
	case MethodCreate, MethodUpdate:
		if _, _, err := c.policy(ctx, false); err != nil {
			return nil, err
		}
		return nil, s.mutate(ctx, p.UserID, func(_ *store.Tx, d *credDoc) error {
			if method == MethodUpdate {
				return s.updateNamed(p.UserID, d, rid, body)
			}
			_, err := s.createNamed(p.UserID, d, body)
			return err
		})
	case MethodDelete:
		all, smbKnown, err := c.resources(ctx, p.UserID)
		if err != nil {
			return nil, err
		}
		return nil, s.mutate(ctx, p.UserID, func(_ *store.Tx, d *credDoc) error {
			return deleteNamed(d, rid, enabled, all, smbKnown)
		})
	case MethodImport:
		pass, _ := field(body, "passphrase")
		_, err := s.importLegacy(ctx, c, p.UserID, pass)
		return nil, err
	}
	return nil, fault.New(fault.InvalidRequest, "")
}

// applyAssignment assigns, replaces or removes the password of one
// resource (apply_native_assignment). The resource must still be the one
// the intent was prepared for, and the stored assignment the one the page
// saw.
func (s *Service) applyAssignment(ctx context.Context, c *credentials, p principal.Principal, revision, token string, mutation jsontext.Value) error {
	if _, _, err := c.policy(ctx, false); err != nil {
		return err
	}
	in, err := c.intents.lookup(p, revision, token, false)
	if err != nil {
		return err
	}
	resID, _ := field(mutation, "resource_id")
	all, _, err := c.resources(ctx, p.UserID)
	if err != nil {
		return err
	}
	var matches []Resource
	for _, r := range all {
		if sameJSON(pyjson.String(r.ID), resID) {
			matches = append(matches, r)
		}
	}
	if !in.hasResource || len(matches) != 1 || matches[0].Fingerprint != in.frozen {
		return fault.New(fault.PreviewChanged, "")
	}
	r := matches[0]
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
	if _, err := c.intents.lookup(p, revision, token, true); err != nil {
		return err
	}
	method, _ := field(mutation, "method")
	return s.mutate(ctx, p.UserID, func(_ *store.Tx, d *credDoc) error {
		previous, ok := d.assignment(r.ID)
		if !ok {
			previous = nil
		}
		if !sameJSON(assignmentJSON(previous), assignmentJSON(in.prior)) {
			return fault.New(fault.PreviewChanged, "")
		}
		credID, _ := field(mutation, "credential_id")
		if string(method) == `"create"` {
			rec, err := s.createNamed(p.UserID, d, mutation)
			if err != nil {
				return err
			}
			credID = pyjson.String(rec.ID)
		}
		if credID.Kind() == 'n' {
			d.unassign(r.ID)
			return nil
		}
		if confirm, _ := field(mutation, "confirm_target"); confirm.Kind() != 't' || !r.Password {
			return fault.New(fault.ConfirmationRequired, "")
		}
		rec, err := record(d, credID)
		if err != nil {
			return err
		}
		if previous != nil && previous.CredentialID == rec.ID && previous.Fingerprint == r.Fingerprint {
			return nil
		}
		d.assign(Assignment{ResourceID: r.ID, CredentialID: rec.ID, Fingerprint: r.Fingerprint, Generation: randomHex(32)})
		return nil
	})
}
