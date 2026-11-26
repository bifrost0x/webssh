package hosts

import (
	"encoding/json/jsontext"
	"regexp"
	"strings"
	"unicode"
)

// Catalogs of app/host_catalog.py that saved hosts are validated against.
// Detection itself (app/host_platform.py) is not part of this release; only
// the stored facts are kept and checked.

func set(items ...string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, item := range items {
		m[item] = true
	}
	return m
}

// platforms is PLATFORMS.
var platforms = set(
	"server", "proxmox", "raspberrypi", "homeassistant", "truenas",
	"opnsense", "ubuntu", "debian", "fedora", "archlinux", "alpinelinux",
	"linux", "apple", "freebsd", "docker",
	"proxmoxbackup", "rockylinux", "almalinux", "redhat", "centos", "opensuse",
	"nixos", "manjaro", "endeavouros", "linuxmint", "popos", "kalilinux",
	"gentoo", "voidlinux", "unraid", "synology", "qnap", "openwrt", "pfsense",
	"windows", "mikrotik", "cisco", "ubiquiti", "embedded",
)

// roles is ROLES.
var roles = set(
	"hypervisor", "backup", "storage", "container", "docs", "photos", "media", "cloud",
	"smarthome", "network", "monitoring", "dev", "passwords", "database", "web",
	"workstation", "server",
)

// families are the values of FAMILIES, virtKinds VIRT_KINDS and
// containerAccess CONTAINER_ACCESS.
var (
	families        = set("debian", "ubuntu", "redhat", "fedora", "opensuse", "archlinux", "alpinelinux", "gentoo")
	virtKinds       = set("bare-metal", "vm", "lxc", "container", "wsl")
	containerAccess = set("ok", "denied", "none")
	osIDPattern     = regexp.MustCompile(`^[a-z0-9._-]{1,32}$`)
	osVersion       = regexp.MustCompile(`^[0-9][0-9A-Za-z._-]{0,15}$`)
)

func inCatalog(catalog map[string]bool, v jsontext.Value) bool {
	s, ok := asString(v)
	return ok && catalog[s]
}

// identityFacts maps the stored identity facts to their checks
// (_IDENTITY_FACTS and _IDENTITY_VALUES).
var identityFacts = map[string]func(jsontext.Value) bool{
	"detected_family":           func(v jsontext.Value) bool { return inCatalog(families, v) },
	"detected_os_id":            func(v jsontext.Value) bool { return matches(osIDPattern, v) },
	"detected_os_version":       func(v jsontext.Value) bool { return matches(osVersion, v) },
	"detected_virt":             func(v jsontext.Value) bool { return inCatalog(virtKinds, v) },
	"detected_container_access": func(v jsontext.Value) bool { return inCatalog(containerAccess, v) },
	"detected_guests": func(v jsontext.Value) bool {
		n, ok := asInt(v)
		return ok && n >= 0 && n <= 9999
	},
	"detected_graphical": isBool,
}

func matches(re *regexp.Regexp, v jsontext.Value) bool {
	s, ok := asString(v)
	return ok && re.MatchString(s)
}

// validStoredFact is _valid_stored_fact for the facts dropped on load.
func validStoredFact(field string, v jsontext.Value) bool {
	switch field {
	case "detection_state":
		s, ok := asString(v)
		return ok && (s == "detected" || s == "unavailable")
	case "platform_checked_at":
		return v.Kind() == '0'
	case "role_override":
		s, ok := asString(v)
		return ok && (s == "auto" || roles[s])
	case "authenticated_greeting":
		s, ok := asString(v)
		return ok && (s == "" || platforms[s])
	}
	return identityFacts[field](v)
}

// droppedFacts are the fields _drop_invalid_stored_facts checks.
var droppedFacts = []string{
	"detected_family", "detected_os_id", "detected_os_version", "detected_virt",
	"detected_container_access", "detected_guests", "detected_graphical",
	"detection_state", "platform_checked_at", "role_override", "authenticated_greeting",
}

// endpointFacts is _ENDPOINT_FACTS: what a detection learned about one
// login on one host. It stays while the endpoint stays.
var endpointFacts = []string{
	"detected_family", "detected_os_id", "detected_os_version", "detected_virt",
	"detected_container_access", "detected_guests", "detected_graphical",
	"detected_services", "services_checked_at", "detected_maintenance",
	"detection_state", "platform_checked_at", "authenticated_greeting",
}

// groupKey is _group_key: the stripped group, case-folded. The fold is an
// equivalence like str.casefold() for the comparison it serves; of the
// multi-character folds only ß is mapped.
func groupKey(group string) string {
	var b strings.Builder
	for _, r := range pyStrip(group) {
		switch r {
		case 'ß', 'ẞ':
			b.WriteString("ss")
		default:
			b.WriteRune(unicode.ToLower(unicode.ToUpper(r)))
		}
	}
	return b.String()
}
