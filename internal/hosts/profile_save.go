package hosts

import (
	"context"
	"encoding/json/jsontext"
	"slices"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
	"github.com/bifrost0x/webssh/internal/store"
)

var (
	errProfileNotFound = fault.New(fault.NotFound, "Profile not found")
	errJumpNotFound    = fault.New(fault.NotFound, "Jump host not found")
	errSOCKSNotFound   = fault.New(fault.ValidationError, "SOCKS proxy not found") // Python: not in the not-found list
	errKeyNotFound     = fault.New(fault.ValidationError, "SSH key not found")
)

// SaveProfile creates or updates a saved host of owner (upsert_profile).
// An update keeps every field the form does not send, including fields
// this release does not know, the detected facts of the same endpoint and
// the position in the group.
func (s *Service) SaveProfile(ctx context.Context, owner int64, req protocol.HostsProfileSave) (jsontext.Value, error) {
	p := profilePayload(req)
	d, err := validateProfile(p)
	if err != nil {
		return nil, err
	}
	if d.keyID != "" {
		if err := s.checkKey(ctx, owner, d.keyID); err != nil {
			return nil, err
		}
	}
	var saved record
	err = s.DB.Write(ctx, func(tx *store.Tx) error {
		all, err := loadStores(ctx, tx, owner)
		if err != nil {
			return err
		}
		profiles := all["profiles"]
		index := -1
		if truthy(p.get("id")) {
			if id, ok := asString(p.get("id")); ok {
				index = find(profiles, id)
			}
		}
		var existing *record
		if index >= 0 {
			existing = &profiles[index]
		}
		if err := postConnect(&d.rec, p, existing); err != nil {
			return err
		}
		finishProfile(&d, p)
		if err := checkRoutes(&d.rec, all); err != nil {
			return err
		}
		next := slices.Clone(profiles)
		now := jsonString(isoUTC(s.now()))
		switch {
		case truthy(p.get("id")) && index < 0:
			return errProfileNotFound
		case index >= 0:
			saved, err = mergeProfile(profiles, index, d, p, now)
		default:
			saved, err = createProfile(profiles, d, jsonString(s.newID()), now)
		}
		if err != nil {
			return err
		}
		if index >= 0 {
			next[index] = saved
		} else {
			next = append(next, saved)
		}
		if err := checkBudgets(&saved, existing, profileBudgets, true); err != nil {
			return err
		}
		if !validProfile(&saved) {
			return fault.New(fault.ValidationError, "Failed to save profile")
		}
		if err := checkGrowth(s.Limits, profileKind, all, next); err != nil {
			return err
		}
		return replace(ctx, tx, profileTable, owner, next)
	})
	if err != nil {
		return nil, classify(err, "Failed to save profile")
	}
	return publicProfile(saved), nil
}

func (s *Service) checkKey(ctx context.Context, owner int64, keyID string) error {
	if s.Keys == nil {
		return errKeyNotFound
	}
	ok, err := s.Keys.HasKey(ctx, owner, keyID)
	if err != nil {
		return fault.Wrap(fault.StorageError, err, "Failed to save profile")
	}
	if !ok {
		return errKeyNotFound
	}
	return nil
}

// checkRoutes refuses references to a jump host or SOCKS5 proxy the user
// does not have; the check runs in the transaction that stores the host.
func checkRoutes(r *record, all stores) error {
	if id, ok := r.str("jump_host_id"); ok && id != "" && find(all["jump_hosts"], id) < 0 {
		return errJumpNotFound
	}
	if id, ok := r.str("socks_proxy_id"); ok && id != "" && find(all["socks_proxies"], id) < 0 {
		return errSOCKSNotFound
	}
	return nil
}

func createProfile(profiles []record, d draft, id, now jsontext.Value) (record, error) {
	if err := herdrModeError(&d.rec); err != nil {
		return record{}, err
	}
	r := d.rec.clone()
	r.set("id", id)
	r.set("sort_order", jsonInt(nextSortOrder(profiles, groupKey(d.group), nil)))
	r.set("created_at", now)
	r.set("updated_at", now)
	return r, nil
}

// mergeProfile is the update branch of upsert_profile.
func mergeProfile(profiles []record, index int, d draft, p payload, now jsontext.Value) (record, error) {
	existing := &profiles[index]
	id, _ := existing.str("id")
	existingKey := recordGroupKey(existing)
	targetKey := existingKey
	if d.hasGroup {
		targetKey = groupKey(d.group)
	}
	var r record
	for _, m := range existing.members {
		if !slices.Contains(profileFields, m.name) {
			r.members = append(r.members, m)
		}
	}
	for _, m := range d.rec.members {
		r.set(m.name, m.value)
	}
	r.set("id", jsonString(id))
	created, ok := existing.get("created_at")
	if !ok {
		created = now
	}
	r.set("created_at", created)
	r.set("updated_at", now)
	copyField := func(field string) {
		if v, ok := existing.get(field); ok {
			r.set(field, v)
		}
	}
	if !p.has("platform_icon") {
		copyField("platform_icon")
	}
	sameEndpoint := endpointOf(existing) == endpointOf(&r)
	if v, ok := existing.get("detected_platform"); sameEndpoint && ok && inCatalog(platforms, v) {
		r.set("detected_platform", v)
	}
	if sameEndpoint {
		for _, field := range endpointFacts {
			copyField(field)
		}
	}
	if !p.has("role_override") {
		copyField("role_override")
	}
	if v, ok := existing.get("greeting_platform"); !p.has("greeting_platform") && ok && inCatalog(platforms, v) &&
		sameAddress(existing, &r) {
		r.set("greeting_platform", v)
	}
	if v, ok := existing.get("group"); !p.has("group") && ok && truthy(v) {
		r.set("group", v)
	}
	if v, _ := existing.get("favorite"); !p.has("favorite") && string(v) == "true" {
		r.set("favorite", jsonTrue)
	}
	for _, field := range []string{"use_tmux", "herdr", "use_herdr", "legacy_algorithms"} {
		if !p.has(field) {
			copyField(field)
		}
	}
	if err := herdrModeError(&r); err != nil {
		return record{}, err
	}
	if existingKey == targetKey {
		if v, ok := existing.get("sort_order"); ok && sortOrderValid(v) {
			r.set("sort_order", v)
		} else {
			members := orderedGroup(profiles, existingKey, nil)
			r.set("sort_order", jsonInt(int64(slices.Index(members, index))))
		}
	} else {
		r.set("sort_order", jsonInt(nextSortOrder(profiles, targetKey, &id)))
	}
	return r, nil
}

// endpointOf is host_platform.endpoint as a comparable value: canonical
// host, port, user and route, or "" where Python returns None.
func endpointOf(r *record) string {
	host, ok := canonicalHost(r.text("host"))
	if !ok {
		return ""
	}
	username, ok := r.str("username")
	port := int64(22)
	if v, has := r.get("port"); has {
		n, isInt := asInt(v)
		if !isInt {
			return ""
		}
		port = n
	}
	if !ok || username == "" || port < 1 || port > 65535 {
		return ""
	}
	route := func(field string) string {
		v, _ := r.get(field)
		if !truthy(v) {
			return "null"
		}
		return string(v)
	}
	key, _ := jsontext.AppendQuote(nil, host)
	return string(key) + "|" + string(jsonInt(port)) + "|" + string(jsonString(username)) + "|" +
		route("jump_host_id") + "|" + route("socks_proxy_id")
}

// sameAddress compares (host, port) with port 22 for a missing one, as
// the greeting rule does.
func sameAddress(a, b *record) bool {
	port := func(r *record) string {
		if v, ok := r.get("port"); ok {
			return string(v)
		}
		return "22"
	}
	ha, _ := a.get("host")
	hb, _ := b.get("host")
	return string(ha) == string(hb) && port(a) == port(b)
}

// herdrModeError is _herdr_mode_error.
func herdrModeError(r *record) error {
	if v, _ := r.get("use_herdr"); string(v) != "true" {
		return nil
	}
	if v, _ := r.get("herdr"); string(v) != "true" {
		return invalid("Herdr session mode requires the Herdr option")
	}
	if v, _ := r.get("use_tmux"); string(v) == "true" {
		return invalid("A host can use either tmux or Herdr, not both")
	}
	if mode, _ := startupMode(r.get); string(mode) != `"none"` {
		return invalid("Herdr session mode cannot be combined with startup commands")
	}
	return nil
}

// publicProfile is _public_profile: tailscale_authorized is derived for
// the response and never stored. Tailscale SSH is not part of this
// release, so no such host is authorized for launch.
func publicProfile(r record) jsontext.Value {
	out := r.clone()
	out.del("tailscale_authorized")
	if s, _ := out.str("auth_type"); s == "tailscale" {
		out.set("tailscale_authorized", jsonFalse)
	}
	return out.encode()
}

// classify keeps classified errors and turns every other failure into a
// storage error with the Python message; the cause stays for the log.
func classify(err error, message string) error {
	if err == nil {
		return nil
	}
	if _, ok := fault.From(err); ok {
		return err
	}
	return fault.Wrap(fault.StorageError, err, message)
}
