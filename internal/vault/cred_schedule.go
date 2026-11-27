package vault

import (
	"context"
	"encoding/json/jsontext"
	"maps"
	"slices"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/pyjson"
)

// RecordFingerprint is profile_fingerprint of app/automation_store.py for
// a stored or frozen record given as JSON (a saved host with its
// route_fingerprint, a jump host, a SOCKS proxy, an SMB share): the
// security-relevant members, missing ones as null, digested like
// digest(). ok is false for a record that is not an object or holds a
// float, which the Python release could not have frozen.
func RecordFingerprint(v jsontext.Value) (string, bool) {
	if v.Kind() != '{' {
		return "", false
	}
	member := func(name string) jsontext.Value { return memberOr(v, name) }
	fields := []pyjson.Member{}
	for _, name := range []string{"id", "host", "port", "username", "auth_type", "key_id", "jump_host_id"} {
		fields = append(fields, pyjson.Member{Name: name, Value: member(name)})
	}
	if s, ok := pyjson.Get(v, "socks_proxy_id"); ok && truthy(s) {
		fields = append(fields, pyjson.Member{Name: "socks_proxy_id", Value: s})
	}
	kind, _ := stringMember(v, "kind")
	switch ResourceKind(kind) {
	case ResourceJump, ResourceSMB, ResourceSOCKS:
		fields = append(fields, pyjson.Member{Name: "kind", Value: pyjson.String(kind)})
	}
	if ResourceKind(kind) == ResourceSOCKS {
		dns := jsonTrue
		if d, ok := pyjson.Get(v, "remote_dns"); ok {
			dns = d
		}
		fields = append(fields, pyjson.Member{Name: "remote_dns", Value: dns})
	}
	if ResourceKind(kind) == ResourceSMB {
		domain := pyjson.String("")
		if d, ok := pyjson.Get(v, "domain"); ok {
			domain = d
		}
		fields = append(fields, pyjson.Member{Name: "domain", Value: domain}, pyjson.Member{Name: "share", Value: member("share")})
	}
	if r, ok := pyjson.Get(v, "route_fingerprint"); ok && truthy(r) {
		fields = append(fields, pyjson.Member{Name: "route_fingerprint", Value: r})
	}
	return pythonDigest(pyjson.Object(fields))
}

// ScheduleBinding is the binding of an approved schedule to the saved
// passwords of its password hops (schedule_generations of
// app/credential_service.py): the account's incarnation, the revision of
// the saved-password switch and, per resource, the generation of its
// assignment and the version of the assigned password. Any change of
// these values ends the approval.
func ScheduleBinding(incarnation, policy string, records map[string][2]string) jsontext.Value {
	ids := slices.Sorted(maps.Keys(records))
	members := make([]pyjson.Member, 0, len(ids))
	for _, id := range ids {
		r := records[id]
		members = append(members, pyjson.Member{Name: id, Value: pyjson.Array([]jsontext.Value{pyjson.String(r[0]), pyjson.String(r[1])})})
	}
	return pyjson.Object([]pyjson.Member{
		{Name: "incarnation", Value: pyjson.String(incarnation)},
		{Name: "policy", Value: pyjson.String(policy)},
		{Name: "records", Value: pyjson.Object(members)},
	})
}

// ScheduleBinding returns the binding of the frozen password hops of a
// schedule as they are now. Every hop must still be the resource it was
// (credential_target_changed) and have a saved password assigned to that
// target (credential_missing); saved passwords must be on
// (credentials_disabled). Only assigned passwords count: the passphrase
// vault of the browser was never usable without a signed-in session.
func (s *Service) ScheduleBinding(ctx context.Context, userID int64, hops []jsontext.Value) (jsontext.Value, error) {
	c, err := s.credentials()
	if err != nil {
		return nil, err
	}
	_, revision, err := c.policy(ctx, false)
	if err != nil {
		return nil, err
	}
	all, _, err := c.resources(ctx, userID)
	if err != nil {
		return nil, err
	}
	d, err := s.readDoc(ctx, userID)
	if err != nil {
		return nil, err
	}
	records := map[string][2]string{}
	for _, hop := range hops {
		id, _ := stringMember(hop, "id")
		current, err := resolve(all, id)
		if err != nil {
			return nil, err
		}
		want, ok := RecordFingerprint(hop)
		if !ok || current.Fingerprint == "" || current.Fingerprint != want {
			return nil, fault.New(fault.CredentialTargetChanged, "")
		}
		a, ok := d.assignment(id)
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
		records[id] = [2]string{a.Generation, rec.Version}
	}
	incarnation, err := c.Accounts.Incarnation(ctx, userID)
	if err != nil {
		return nil, fault.Wrap(fault.StorageError, err, "")
	}
	return ScheduleBinding(incarnation, revision, records), nil
}

// SchedulePassword returns the saved password assigned to one frozen hop
// of an approved schedule (schedule_password of the Python release): the
// hop must pass ScheduleBinding first. The caller clears the secret and
// never logs it.
func (s *Service) SchedulePassword(ctx context.Context, userID int64, hop jsontext.Value) ([]byte, error) {
	if _, err := s.ScheduleBinding(ctx, userID, []jsontext.Value{hop}); err != nil {
		return nil, err
	}
	id, _ := stringMember(hop, "id")
	d, err := s.readDoc(ctx, userID)
	if err != nil {
		return nil, err
	}
	a, ok := d.assignment(id)
	if !ok {
		return nil, fault.New(fault.CredentialMissing, "")
	}
	rec, ok := d.record(a.CredentialID)
	if !ok {
		return nil, fault.New(fault.CredentialMissing, "")
	}
	return s.open(userID, rec)
}
