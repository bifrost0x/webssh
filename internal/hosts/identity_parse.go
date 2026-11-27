package hosts

import (
	"errors"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"
)

// Identity is what the probe established about a host (parse_identity).
// Every value is a catalog id, an enum or a checked pattern; anything the
// host printed that does not map is dropped. Empty strings and nil
// pointers are Python's None.
type Identity struct {
	// State is "detected" or "unavailable" (output that did not come from
	// the probe: a forced command, a menu, a banner).
	State           string
	Platform        string
	Family          string
	OSID            string
	OSVersion       string
	Virt            string
	Graphical       *bool
	Guests          *int
	Services        []string
	ContainerAccess string
}

// Probe answers.
const (
	StateDetected    = "detected"
	StateUnavailable = "unavailable"
)

// MaxIdentityOutput is the largest probe answer that is parsed.
const MaxIdentityOutput = 8192

var errIdentity = errors.New("hosts: invalid identity facts")

var (
	osReleaseKeys = set("ID", "ID_LIKE", "VERSION_ID", "VARIANT_ID")
	singleKeys    = set("ID", "ID_LIKE", "VERSION_ID", "VARIANT_ID", "kernel", "model", "virt", "target", "guests")
	repeatedKeys  = set("marker", "service", "unit", "snap", "image", "engine")
	piModel       = regexp.MustCompile(`^Raspberry Pi [A-Za-z0-9 .+()-]{1,120}$`)
	guestsPattern = regexp.MustCompile(`^[0-9]{1,4}$`)
	engines       = map[string][2]string{"docker:ok": {"docker", "ok"}, "docker:denied": {"docker", "denied"},
		"podman:ok": {"podman", "ok"}, "podman:denied": {"podman", "denied"}}
)

const maxFactLength = 200

// isControl is _CONTROL: C0 controls but the tab, DEL and C1 controls.
func isControl(r rune) bool {
	return r <= 0x08 || (r >= 0x0a && r <= 0x1f) || (r >= 0x7f && r <= 0x9f)
}

func unquote(v string) string {
	if len(v) >= 2 && v[0] == v[len(v)-1] && (v[0] == '"' || v[0] == '\'') {
		return v[1 : len(v)-1]
	}
	return v
}

// probeLines splits like the probe prints: only LF ends a line (a hostile
// value may carry U+2028 and similar), a trailing CR is dropped.
func probeLines(text string) []string {
	lines := strings.Split(text, "\n")
	for i, l := range lines {
		lines[i] = strings.TrimSuffix(l, "\r")
	}
	return lines
}

// ParseIdentity is parse_identity. It fails only for text longer than
// MaxIdentityOutput bytes or that is not UTF-8.
func ParseIdentity(text string) (Identity, error) {
	if len(text) > MaxIdentityOutput || !utf8.ValidString(text) {
		return Identity{}, errIdentity
	}
	single, repeated, duplicates := map[string]string{}, map[string][]string{}, map[string]bool{}
	for _, line := range probeLines(text) {
		// The probe never prints C0, DEL or C1 controls. A line with one
		// came from a shell startup file or is hostile; it is dropped
		// whole, so no control character can start a new key.
		if strings.ContainsFunc(line, isControl) {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		value = pyStrip(value)
		if !found || pyLen(value) > maxFactLength {
			continue
		}
		switch {
		case singleKeys[key]:
			if _, seen := single[key]; seen {
				duplicates[key] = true
			}
			if osReleaseKeys[key] {
				value = unquote(value)
			}
			single[key] = value
		case repeatedKeys[key]:
			repeated[key] = append(repeated[key], value)
		}
	}
	id := Identity{State: StateUnavailable, Services: []string{}}
	if _, ok := single["kernel"]; !ok {
		return id, nil
	}
	// A key the probe prints once but that came twice cannot be trusted.
	facts := func(key string) string {
		if duplicates[key] {
			return ""
		}
		return single[key]
	}
	osID := facts("ID")
	if !osIDPattern.MatchString(osID) {
		osID = ""
	}
	for _, token := range strings.FieldsFunc(facts("ID_LIKE"), pyIsSpace) {
		if f, ok := familyOf[token]; ok {
			id.Family = f
			break
		}
	}
	released := osIDPlatforms[osID]
	if released == "" {
		released = id.Family
	}
	markers := repeated["marker"]
	for _, m := range markerPlatforms {
		if slices.Contains(markers, m[0]) {
			id.Platform = m[1]
			break
		}
	}
	if id.Platform == "" && piModel.MatchString(facts("model")) {
		id.Platform = "raspberrypi"
	}
	if id.Platform == "" {
		id.Platform = released
		if id.Platform == "" {
			id.Platform = kernelPlatforms[facts("kernel")]
		}
	}
	if _, known := osIDPlatforms[osID]; osID != "" && !known {
		id.OSID = osID
	}
	// VERSION_ID numbers the system os-release names. On Proxmox, TrueNAS
	// or a Raspberry Pi board that is the base distribution, not the
	// platform shown, so it is kept only next to its own system.
	if version := facts("VERSION_ID"); ((released != "" && released == id.Platform) || id.OSID != "") && osVersion.MatchString(version) {
		id.OSVersion = version
	}
	id.State = StateDetected
	id.Virt = virtMap[facts("virt")]
	if target := facts("target"); target != "" {
		graphical := target == "graphical.target"
		id.Graphical = &graphical
	}
	if g := facts("guests"); guestsPattern.MatchString(g) {
		n := 0
		for _, c := range g {
			n = n*10 + int(c-'0')
		}
		id.Guests = &n
	}
	id.Services, id.ContainerAccess = detectedServices(repeated)
	return id, nil
}

func lookupPair(pairs [][2]string, key string) (string, bool) {
	for _, p := range pairs {
		if p[0] == key {
			return p[1], true
		}
	}
	return "", false
}

// pyLower is str.lower() for the characters whose lowering Go's
// unicode.ToLower does not reproduce.
func pyLower(s string) string {
	return strings.ReplaceAll(strings.ToLower(strings.ReplaceAll(s, "İ", "i̇")), "İ", "i̇")
}

func detectedServices(repeated map[string][]string) ([]string, string) {
	found := map[string]bool{}
	for _, v := range repeated["service"] {
		if services[v] {
			found[v] = true
		}
	}
	for _, v := range repeated["unit"] {
		if s, ok := lookupPair(serviceUnits, v); ok {
			found[s] = true
		}
	}
	for _, v := range repeated["snap"] {
		if s, ok := lookupPair(serviceSnaps, v); ok {
			found[s] = true
		}
	}
	for _, v := range repeated["image"] {
		if s := matchImage(pyLower(v)); s != "" {
			found[s] = true
		}
	}
	access := map[string]bool{}
	for _, v := range repeated["engine"] {
		if e, ok := engines[v]; ok {
			found[e[0]] = true
			access[e[1]] = true
		}
	}
	rank := func(name string) int {
		switch {
		case priorityServices[name]:
			return 0
		case infrastructureServices[name]:
			return 2
		}
		return 1
	}
	kept := make([]string, 0, len(found))
	for s := range found {
		kept = append(kept, s)
	}
	slices.SortFunc(kept, func(a, b string) int {
		if d := rank(a) - rank(b); d != 0 {
			return d
		}
		return strings.Compare(a, b)
	})
	kept = kept[:min(len(kept), maxServices)]
	slices.Sort(kept)
	// "denied" also covers a stopped daemon or a timeout; one readable
	// engine is enough for "ok".
	containerAccess := ""
	switch {
	case access["ok"]:
		containerAccess = "ok"
	case len(access) > 0:
		containerAccess = "denied"
	}
	return kept, containerAccess
}
