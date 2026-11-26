package hosts

import (
	"encoding/json/jsontext"
	"slices"
)

// The record validators of the Python stores. A stored record always
// satisfies its validator; the import refuses a record that does not, as
// Python refused the whole document.

func optionalString(r *record, field string, allowNull bool) bool {
	v, ok := r.get(field)
	if !ok {
		return true
	}
	_, isText := asString(v)
	return isText || (allowNull && isNull(v))
}

func optionalBool(r *record, field string) bool {
	v, ok := r.get(field)
	return !ok || isBool(v)
}

func optionalIn(r *record, field string, allowed ...string) bool {
	v, ok := r.get(field)
	if !ok {
		return true
	}
	s, isText := asString(v)
	if !isText {
		return false
	}
	return slices.Contains(allowed, s)
}

// validProfile is _valid_profile.
func validProfile(r *record) bool {
	if r.has("tailscale_authorized") {
		return false
	}
	if _, ok := r.str("id"); !ok {
		return false
	}
	if _, ok := r.str("name"); !ok {
		return false
	}
	for _, field := range []string{"host", "username", "startup_commands", "command_id",
		"command_set_id", "parameters_override", "created_at", "updated_at", "group"} {
		if !optionalString(r, field, false) {
			return false
		}
	}
	for _, field := range []string{"key_id", "jump_host_id", "socks_proxy_id"} {
		if !optionalString(r, field, true) {
			return false
		}
	}
	if socks, _ := r.get("socks_proxy_id"); truthy(socks) {
		s, _ := asString(socks)
		jump, _ := r.get("jump_host_id")
		if pyLen(s) > 64 || truthy(jump) || r.text("auth_type") == "tailscale" {
			return false
		}
	}
	if v, ok := r.get("port"); ok && !isIntegerToken(v) {
		return false
	}
	if !optionalIn(r, "auth_type", "password", "key", "tailscale") ||
		!optionalIn(r, "startup_mode", "none", "free_text", "command", "command_set") {
		return false
	}
	for _, field := range []string{"use_tmux", "favorite", "herdr", "use_herdr"} {
		if !optionalBool(r, field) {
			return false
		}
	}
	if v, ok := r.get("sort_order"); ok && !sortOrderValid(v) {
		return false
	}
	if !optionalString(r, "greeting_platform", false) || !optionalString(r, "authenticated_greeting", false) {
		return false
	}
	if v, ok := r.get("detected_services"); ok && !stringList(v) {
		return false
	}
	if v, ok := r.get("services_checked_at"); ok && v.Kind() != '0' {
		return false
	}
	return true
}

func stringList(v jsontext.Value) bool {
	if v.Kind() != '[' {
		return false
	}
	var items []jsontext.Value
	if err := unmarshalArray(v, &items); err != nil {
		return false
	}
	for _, item := range items {
		if item.Kind() != '"' {
			return false
		}
	}
	return true
}

// validJumpHost is _valid_jump_host.
func validJumpHost(r *record) bool {
	for _, field := range []string{"id", "name", "host", "username", "auth_type"} {
		if _, ok := r.str(field); !ok {
			return false
		}
	}
	if v, ok := r.get("port"); !ok || !isIntegerToken(v) {
		return false
	}
	if a := r.text("auth_type"); a != "password" && a != "key" {
		return false
	}
	return optionalString(r, "key_id", true) && optionalString(r, "created_at", false)
}

// validSOCKSProxy is _valid_socks_proxy: exactly the eight fields.
func validSOCKSProxy(r *record) bool {
	if len(r.members) != len(socksFields) {
		return false
	}
	for _, field := range socksFields {
		if !r.has(field) {
			return false
		}
	}
	for _, field := range []string{"id", "name", "host", "username", "auth_type", "created_at"} {
		if _, ok := r.str(field); !ok {
			return false
		}
	}
	id, name, host := r.text("id"), r.text("name"), r.text("host")
	if id == "" || pyLen(id) > 64 || pyStrip(name) == "" || !validHost(host) {
		return false
	}
	port, _ := r.get("port")
	if n, ok := asInt(port); !ok || n < 1 || n > 65535 {
		return false
	}
	auth, user := r.text("auth_type"), r.text("username")
	if (auth != "none" && auth != "password") || (auth == "none" && user != "") || (auth == "password" && user == "") {
		return false
	}
	if v, _ := r.get("remote_dns"); !isBool(v) {
		return false
	}
	return checkBudgets(r, nil, socksBudgets, false) == nil
}

// dropInvalidFacts is _drop_invalid_stored_facts: identity facts and roles
// that do not fit (a newer release, a hand edit) go and are detected again.
func dropInvalidFacts(r *record) int {
	dropped := 0
	for _, field := range droppedFacts {
		if v, ok := r.get(field); ok && !validStoredFact(field, v) {
			r.del(field)
			dropped++
		}
	}
	return dropped
}
