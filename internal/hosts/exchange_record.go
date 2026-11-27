package hosts

import (
	"encoding/json/jsontext"
	"slices"
	"strings"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/pyjson"
)

// Limits and texts of app/profile_exchange.py.
const (
	exchangeMaxInputBytes = 64 << 10
	exchangeMaxRecords    = 100
	socksRouteWarning     = "SOCKS5 route not exported"
)

// exchangeFields are the members a host of an exchange document may have.
var exchangeFields = []string{
	"name", "host", "port", "username", "group", "favorite", "use_tmux",
	"herdr", "use_herdr", "requires_key", "jump_alias", "auth_type", "platform_icon",
	"role_override", "socks_route_omitted", "warnings",
}

// exchangeError is a refused exchange document. The text is matched
// against the public messages of the route; any other text is shown as
// the generic message.
func exchangeError(message string) error { return fault.New(fault.ValidationError, message) }

var errUnsupportedFields = exchangeError("Host document contains unsupported fields.")

// selectorCheck tells whether a "user:target" username is a valid
// gateway selector (parse_selector).
type selectorCheck func(username string) bool

func isTrue(v jsontext.Value) bool { return v.Kind() == 't' }

// onlySOCKSWarning is values['warnings'] == [SOCKS_ROUTE_WARNING].
func onlySOCKSWarning(v jsontext.Value) bool {
	items, ok := pyjson.Items(v)
	if !ok || len(items) != 1 {
		return false
	}
	s, ok := asString(items[0])
	return ok && s == socksRouteWarning
}

// textOf is _text(value, maximum) for a decoded value.
func textOf(v jsontext.Value, maximum int) bool {
	s, ok := asString(v)
	return ok && pyTextValue(s, maximum)
}

func exchangeUsername(v jsontext.Value, selector selectorCheck) bool {
	if !textOf(v, 128) {
		return false
	}
	s, _ := asString(v)
	if strings.Contains(s, ":") {
		return selector != nil && selector(s)
	}
	return s == "" || exchangeUser.MatchString(s)
}

func inCatalogOrAuto(catalog map[string]bool, v jsontext.Value) bool {
	s, ok := asString(v)
	return ok && (catalog[s] || s == "auto")
}

// exchangeRecord is _record: the preview row of one host, with the
// warnings that explain what must be mapped or why it is blocked.
func exchangeRecord(values record, selector selectorCheck) (record, error) {
	socks, hasSOCKS := values.get("socks_route_omitted")
	if hasSOCKS && !isTrue(socks) {
		return record{}, errUnsupportedFields
	}
	if w, ok := values.get("warnings"); ok && (!isTrue(socks) || !onlySOCKSWarning(w)) {
		return record{}, errUnsupportedFields
	}
	var row record
	for _, m := range values.members {
		if slices.Contains(exchangeFields, m.name) {
			row.set(m.name, m.value)
		}
	}
	setDefault := func(name string, v jsontext.Value) {
		if !row.has(name) {
			row.set(name, v)
		}
	}
	setDefault("name", jsonString(""))
	name, _ := row.get("name")
	setDefault("host", name)
	setDefault("username", jsonString(""))
	setDefault("port", jsonInt(22))
	setDefault("requires_key", jsonFalse)
	if a, _ := row.str("auth_type"); a == "key" {
		row.set("requires_key", jsonTrue)
	}
	var warnings []string
	blocked := false
	if v, _ := row.get("socks_route_omitted"); truthy(v) {
		blocked = true
		warnings = append(warnings, socksRouteWarning)
	}
	if !validExchangeMetadata(&row, selector) {
		blocked = true
		warnings = append(warnings, "Invalid connection metadata.")
	}
	jump, hasJump := row.get("jump_alias")
	if !hasJump {
		jump = jsonString("")
	}
	requiresJump := truthy(jump)
	requiresKey, _ := row.get("requires_key")
	if a, _ := row.str("auth_type"); a == "tailscale" && (truthy(requiresKey) || requiresJump) {
		blocked = true
		warnings = append(warnings, "Tailscale cannot use a stored key or jump host.")
	}
	if !textOf(jump, 128) {
		blocked = true
		warnings = append(warnings, "This jump-host expression is unsupported.")
	}
	if username, _ := row.get("username"); !truthy(username) {
		warnings = append(warnings, "Choose an SSH username before importing.")
	}
	if truthy(requiresKey) {
		warnings = append(warnings, "Map an existing stored key before importing.")
	}
	if requiresJump {
		warnings = append(warnings, "Map an existing jump host before importing.")
	}
	row.set("warnings", stringArray(warnings))
	row.set("blocked", jsonBool(blocked))
	row.set("requires_jump", jsonBool(requiresJump))
	return row, nil
}

// validExchangeMetadata is the large condition of _record that marks a
// row "Invalid connection metadata.".
func validExchangeMetadata(row *record, selector selectorCheck) bool {
	name, _ := row.get("name")
	host, _ := row.get("host")
	username, _ := row.get("username")
	port, _ := row.get("port")
	requiresKey, _ := row.get("requires_key")
	if !textOf(name, 128) || pyStrip(row.text("name")) == "" {
		return false
	}
	if !textOf(host, 253) || !validHost(row.text("host")) || !exchangeUsername(username, selector) {
		return false
	}
	if n, ok := asInt(port); !ok || n < 1 || n > 65535 {
		return false
	}
	if !isBool(requiresKey) {
		return false
	}
	if a, ok := row.get("auth_type"); ok {
		s, isText := asString(a)
		if !isText || (s != "password" && s != "key" && s != "tailscale") {
			return false
		}
	}
	if v, ok := row.get("platform_icon"); ok && !inCatalogOrAuto(platforms, v) {
		return false
	}
	if v, ok := row.get("role_override"); ok && !inCatalogOrAuto(roles, v) {
		return false
	}
	if v, ok := row.get("group"); ok && !textOf(v, maxGroupLength) {
		return false
	}
	for _, field := range []string{"favorite", "use_tmux", "herdr", "use_herdr"} {
		if v, ok := row.get(field); ok && !isBool(v) {
			return false
		}
	}
	return true
}

func jsonBool(b bool) jsontext.Value {
	if b {
		return jsonTrue
	}
	return jsonFalse
}

func stringArray(list []string) jsontext.Value {
	items := make([]jsontext.Value, len(list))
	for i, s := range list {
		items[i] = jsonString(s)
	}
	return pyjson.Array(items)
}
