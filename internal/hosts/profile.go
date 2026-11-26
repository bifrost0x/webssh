package hosts

import (
	"encoding/json/jsontext"
	"strings"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
)

// payload is a decoded request as Python's dict: the members present.
type payload map[string]jsontext.Value

func (p payload) has(name string) bool { return len(p[name]) > 0 }

// get is dict.get(): absent and null are both "no value" for truthiness.
func (p payload) get(name string) jsontext.Value { return p[name] }

func profilePayload(req protocol.HostsProfileSave) payload {
	p := payload{}
	for name, v := range map[string]jsontext.Value{
		"id": req.ID, "name": req.Name, "platform_icon": req.PlatformIcon,
		"group": req.Group, "host": req.Host, "port": req.Port,
		"username": req.Username, "auth_type": req.AuthType, "key_id": req.KeyID,
		"jump_host_id": req.JumpHostID, "socks_proxy_id": req.SOCKSProxyID,
		"startup_mode": req.StartupMode, "startup_commands": req.StartupCommands,
		"command_id": req.CommandID, "command_set_id": req.CommandSetID,
		"parameters_override": req.ParametersOverride, "use_tmux": req.UseTmux,
		"herdr": req.Herdr, "use_herdr": req.UseHerdr,
		"greeting_platform": req.GreetingPlatform, "favorite": req.Favorite,
		"role_override": req.RoleOverride,
	} {
		if len(v) > 0 {
			p[name] = v
		}
	}
	return p
}

func invalid(message string) error { return fault.New(fault.InvalidValue, message) }

var (
	errTailscalePreview = fault.New(fault.NotAvailableInPreview, "Tailscale SSH hosts cannot be saved in this preview.")
	errGatewayPreview   = fault.New(fault.NotAvailableInPreview, "SSH gateway selectors are not available in this preview.")
	errCommandsPreview  = fault.New(fault.NotAvailableInPreview, "Commands and command sets cannot be assigned in this preview.")
)

// draft is a validated profile before it meets the stored list: the
// fields in the order _validate_profile_payload builds them.
type draft struct {
	rec      record
	keyID    string // set for key authentication
	group    string // normalized; "" for none
	hasGroup bool   // "group" was in the payload
}

// validateProfile is the payload half of _validate_profile_payload, the
// checks before any store is read, in Python's order. Tailscale SSH and
// gateway selectors are refused because this release builds neither.
func validateProfile(p payload) (draft, error) {
	if s, ok := asString(p.get("auth_type")); ok && s == "tailscale" {
		return draft{}, errTailscalePreview
	}
	if p.has("platform_icon") {
		if s, ok := asString(p.get("platform_icon")); !ok || (s != "auto" && !platforms[s]) {
			return draft{}, invalid("Invalid platform icon")
		}
	}
	if p.has("greeting_platform") && !inCatalog(platforms, p.get("greeting_platform")) {
		return draft{}, invalid("Invalid platform icon")
	}
	if p.has("role_override") && !validStoredFact("role_override", p.get("role_override")) {
		return draft{}, invalid("Invalid role")
	}
	if !truthy(p.get("name")) || !truthy(p.get("host")) || !truthy(p.get("username")) || !truthy(p.get("auth_type")) {
		return draft{}, invalid("Missing required fields")
	}
	name, ok := asString(p.get("name"))
	if !ok || pyStrip(name) == "" {
		return draft{}, invalid("Invalid profile name")
	}
	name = pyPrefix(pyStrip(name), 128)
	host, ok := asString(p.get("host"))
	host = pyStrip(host)
	if !ok || !validHost(host) {
		return draft{}, invalid("Invalid host format")
	}
	port := int64(22)
	if truthy(p.get("port")) {
		n, ok := pyInt(p.get("port"))
		if !ok {
			return draft{}, invalid("Invalid port number")
		}
		port = n
	}
	if port < 1 || port > 65535 {
		return draft{}, invalid("Port must be between 1 and 65535")
	}
	username, ok := asString(p.get("username"))
	if ok && strings.Contains(username, ":") {
		return draft{}, errGatewayPreview
	}
	username = pyStrip(username)
	if !ok || !validUsername(username) {
		return draft{}, invalid("Invalid username format")
	}
	authType, _ := asString(p.get("auth_type"))
	if authType != "password" && authType != "key" {
		return draft{}, invalid("Invalid auth_type")
	}
	socks := p.get("socks_proxy_id")
	if p.has("socks_proxy_id") && !isNull(socks) {
		if s, ok := asString(socks); !ok || pyLen(s) > 64 {
			return draft{}, invalid("Invalid SOCKS proxy reference")
		}
	}
	if truthy(socks) && truthy(p.get("jump_host_id")) {
		return draft{}, invalid("A host can use either a jump host or a SOCKS5 proxy, not both")
	}
	d := draft{hasGroup: p.has("group")}
	if d.hasGroup {
		g, ok := asString(p.get("group"))
		if !ok {
			return draft{}, invalid("Invalid group")
		}
		if d.group = pyStrip(g); pyLen(d.group) > maxGroupLength {
			return draft{}, invalid("Group must not exceed 64 characters")
		}
	}
	if p.has("favorite") && !isBool(p.get("favorite")) {
		return draft{}, invalid("favorite must be a boolean")
	}
	if p.has("use_tmux") && !isBool(p.get("use_tmux")) {
		return draft{}, invalid("use_tmux must be a boolean")
	}
	for _, field := range []string{"herdr", "use_herdr"} {
		if p.has(field) && !isBool(p.get(field)) {
			return draft{}, invalid(field + " must be a boolean")
		}
	}
	keyID := p.get("key_id")
	if authType == "key" && !truthy(keyID) {
		return draft{}, invalid("key_id required for key authentication")
	}
	if p.has("key_id") && !isNull(keyID) {
		if _, ok := asString(keyID); !ok {
			return draft{}, invalid("Invalid key reference")
		}
	}
	r := &d.rec
	r.set("name", jsonString(name))
	r.set("host", jsonString(host))
	r.set("port", jsonInt(port))
	r.set("username", jsonString(username))
	r.set("auth_type", jsonString(authType))
	r.set("key_id", jsonNull)
	if authType == "key" {
		d.keyID, _ = asString(keyID)
		r.set("key_id", jsonString(d.keyID))
	}
	return d, nil
}

const maxGroupLength = 64

// finishProfile appends what follows the post-connect fields in
// _validate_profile_payload.
func finishProfile(d *draft, p payload) {
	r := &d.rec
	for _, field := range []string{"platform_icon", "greeting_platform", "role_override"} {
		if p.has(field) {
			r.set(field, p.get(field))
		}
	}
	if d.hasGroup && d.group != "" {
		r.set("group", jsonString(d.group))
	}
	if string(p.get("favorite")) == "true" {
		r.set("favorite", jsonTrue)
	}
	for _, field := range []string{"use_tmux", "herdr", "use_herdr"} {
		if p.has(field) {
			r.set(field, p.get(field))
		}
	}
	if v := p.get("jump_host_id"); truthy(v) {
		r.set("jump_host_id", jsonString(pyPrefix(pyText(v), 64)))
	}
	if v := p.get("socks_proxy_id"); truthy(v) {
		r.set("socks_proxy_id", v)
	}
}

// pyText is str() of a JSON scalar as far as references need it.
func pyText(v jsontext.Value) string {
	if s, ok := asString(v); ok {
		return s
	}
	switch v.Kind() {
	case 't':
		return "True"
	case 'f':
		return "False"
	}
	return string(v)
}

// startupMode is infer_mode.
func startupMode(get func(string) (jsontext.Value, bool)) (jsontext.Value, bool) {
	if v, ok := get("startup_mode"); ok && !isNull(v) {
		return v, true
	}
	for _, c := range []struct{ field, mode string }{
		{"command_set_id", "command_set"}, {"command_id", "command"}, {"startup_commands", "free_text"},
	} {
		if v, ok := get(c.field); ok && truthy(v) {
			return jsonString(c.mode), false
		}
	}
	return jsonString("none"), false
}

const maxStartupCommands = 4096

// normalizeStartupCommands is normalize_startup_commands.
func normalizeStartupCommands(v jsontext.Value) (string, error) {
	s, ok := asString(v)
	if !ok {
		return "", invalid("Startup commands must be text")
	}
	if pyLen(s) > maxStartupCommands {
		return "", invalid("Startup commands must not exceed 4096 characters")
	}
	if strings.ContainsRune(s, 0) {
		return "", invalid("Startup commands must not contain NUL bytes")
	}
	s = strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\r", "\n")
	return s, nil
}

// postConnect is validate_configuration. Commands and command sets are not
// part of this release, so their references cannot be checked: a saved
// host keeps the reference it already has, a new or changed one is
// refused.
func postConnect(r *record, p payload, existing *record) error {
	get := func(name string) (jsontext.Value, bool) { return p[name], p.has(name) }
	modeValue, _ := startupMode(get)
	mode, ok := asString(modeValue)
	if !ok || (mode != "none" && mode != "free_text" && mode != "command" && mode != "command_set") {
		return invalid("Invalid post-connect command mode")
	}
	commandID, setID := truthy(p.get("command_id")), truthy(p.get("command_set_id"))
	if (mode == "command" && setID) || (mode == "command_set" && commandID) || (mode == "free_text" && (commandID || setID)) {
		return invalid("Conflicting post-connect command configuration")
	}
	r.set("startup_mode", jsonString(mode))
	switch mode {
	case "free_text":
		value, ok := get("startup_commands")
		if !ok {
			value = jsonString("")
		}
		text, err := normalizeStartupCommands(value)
		if err != nil {
			return err
		}
		r.set("startup_commands", jsonString(text))
	case "command":
		if !sameReference(existing, mode, "command_id", p) ||
			!sameField(existing, "parameters_override", p) {
			return errCommandsPreview
		}
		r.set("command_id", p.get("command_id"))
		if v := p.get("parameters_override"); p.has("parameters_override") && !isNull(v) {
			r.set("parameters_override", v)
		}
	case "command_set":
		if !sameReference(existing, mode, "command_set_id", p) {
			return errCommandsPreview
		}
		r.set("command_set_id", p.get("command_set_id"))
	}
	return nil
}

// sameReference reports that the stored profile already uses this command
// or command set in this mode.
func sameReference(existing *record, mode, field string, p payload) bool {
	if existing == nil {
		return false
	}
	stored, ok := existing.str(field)
	sent, sentOK := asString(p.get(field))
	storedMode, _ := startupMode(existing.get)
	return ok && sentOK && stored == sent && stored != "" && string(storedMode) == string(jsonString(mode))
}

func sameField(existing *record, field string, p payload) bool {
	stored, ok := existing.get(field)
	sent := p.get(field)
	if !p.has(field) || isNull(sent) {
		return !ok || isNull(stored)
	}
	return ok && string(stored) == string(sent)
}
