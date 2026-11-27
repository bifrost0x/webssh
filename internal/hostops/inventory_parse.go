package hostops

import (
	"errors"
	"math"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"
)

// Limits of the runtime inventory (app/runtime_inventory.py).
const (
	inventoryMaxBytes    = 64 << 10
	maxSystemdServices   = 200
	maxDockerContainers  = 50
	inventoryMaxDescRune = 240
)

var (
	unitNamePattern      = regexp.MustCompile(`^[A-Za-z0-9@_.:-]{1,200}$`)
	containerNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
)

var (
	systemdManagerStates = []string{"starting", "running", "degraded", "maintenance", "stopping", "offline", "unknown"}
	systemdLoadStates    = []string{"loaded", "not-found", "masked", "error", "bad-setting"}
	systemdActiveStates  = []string{"active", "reloading", "inactive", "failed", "activating", "deactivating", "maintenance"}
)

// RuntimeInventory is a parsed runtime inventory. Sections are present only when
// their counters were complete and consistent.
type RuntimeInventory struct {
	Systemd          *SystemdInventory `json:"systemd,omitempty"`
	Docker           *DockerInventory  `json:"docker,omitempty"`
	PermissionDenied []string          `json:"permission_denied,omitempty"`
}

// SystemdInventory is the service manager state with up to 200 services.
type SystemdInventory struct {
	State     string           `json:"state"`
	Total     uint64           `json:"total"`
	Active    uint64           `json:"active"`
	Failed    uint64           `json:"failed"`
	Returned  uint64           `json:"returned"`
	Truncated bool             `json:"truncated"`
	Services  []SystemdService `json:"services"`
}

// SystemdService is one service unit.
type SystemdService struct {
	Unit        string `json:"unit"`
	Load        string `json:"load"`
	Active      string `json:"active"`
	Sub         string `json:"sub"`
	Description string `json:"description"`
}

// DockerInventory is the Docker engine with up to 50 containers.
type DockerInventory struct {
	Version    string            `json:"version"`
	Total      uint64            `json:"total"`
	Running    uint64            `json:"running"`
	Returned   uint64            `json:"returned"`
	Truncated  bool              `json:"truncated"`
	Containers []DockerContainer `json:"containers"`
}

// DockerContainer is one container.
type DockerContainer struct {
	Name   string `json:"name"`
	Status string `json:"status"`
}

// inventoryText is _safe_text of runtime_inventory: no control
// characters, then stripped, 1 to max characters.
func inventoryText(v string, max int) (string, bool) {
	if hasControl(v) {
		return "", false
	}
	v = pyStrip(v)
	if v == "" || runeLen(v) > max {
		return "", false
	}
	return v, true
}

var inventorySingleKeys = map[string]bool{
	"systemd_state": true, "systemd_total": true, "systemd_active": true, "systemd_failed": true,
	"systemd_returned": true, "docker_version": true, "docker_total": true, "docker_running": true,
	"docker_returned": true,
}

// ParseInventory parses the output of the fixed inventory collector
// (parse_runtime_inventory). Untrusted rows that do not match are left
// out; the counters must agree with the rows.
func ParseInventory(text string) (RuntimeInventory, error) {
	if len(text) > inventoryMaxBytes {
		return RuntimeInventory{}, errors.New("hostops: inventory payload too large")
	}
	if !utf8.ValidString(text) {
		return RuntimeInventory{}, errors.New("hostops: inventory payload is not UTF-8")
	}
	values := map[string]string{}
	var services, containers []string
	var inv RuntimeInventory
	for _, line := range splitLines(text) {
		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		switch {
		case inventorySingleKeys[key]:
			values[key] = value
		case key == "systemd_service":
			services = append(services, value)
		case key == "docker_container":
			containers = append(containers, value)
		case key == "permission_denied":
			scope := pyStrip(value)
			if (scope == "systemd" || scope == "docker") && !slices.Contains(inv.PermissionDenied, scope) {
				inv.PermissionDenied = append(inv.PermissionDenied, scope)
			}
		}
	}
	inv.Systemd = parseSystemd(values, services)
	inv.Docker = parseDocker(values, containers)
	return inv, nil
}

// counter is _optional_count: a non-negative integer, present.
func counter(values map[string]string, key string) (uint64, bool) {
	v, ok := values[key]
	if !ok {
		return 0, false
	}
	return parseCount(v, math.MaxUint64)
}

func parseSystemd(values map[string]string, rows []string) *SystemdInventory {
	state := pyStrip(values["systemd_state"])
	total, ok1 := counter(values, "systemd_total")
	active, ok2 := counter(values, "systemd_active")
	failed, ok3 := counter(values, "systemd_failed")
	reported, ok4 := counter(values, "systemd_returned")
	if !slices.Contains(systemdManagerStates, state) || !ok1 || !ok2 || !ok3 || !ok4 ||
		active > total || failed > total || active+failed > total || active+failed < active ||
		reported > total || reported > maxSystemdServices || uint64(len(rows)) != reported {
		return nil
	}
	out := &SystemdInventory{State: state, Total: total, Active: active, Failed: failed, Services: []SystemdService{}}
	for _, row := range rows {
		parts := strings.SplitN(row, "|", 5)
		if len(parts) != 5 {
			continue
		}
		unit, load, act := parts[0], parts[1], parts[2]
		sub, okSub := inventoryText(parts[3], 64)
		desc, okDesc := inventoryText(parts[4], inventoryMaxDescRune)
		if !unitNamePattern.MatchString(unit) || !slices.Contains(systemdLoadStates, load) ||
			!slices.Contains(systemdActiveStates, act) || !okDesc || !okSub {
			continue
		}
		out.Services = append(out.Services, SystemdService{Unit: unit, Load: load, Active: act, Sub: sub, Description: desc})
		out.Returned++
	}
	out.Truncated = total > out.Returned
	return out
}

func parseDocker(values map[string]string, rows []string) *DockerInventory {
	version, okV := inventoryText(values["docker_version"], 64)
	total, ok1 := counter(values, "docker_total")
	running, ok2 := counter(values, "docker_running")
	reported, ok3 := counter(values, "docker_returned")
	if !okV || !ok1 || !ok2 || !ok3 || running > total || reported > total ||
		reported > maxDockerContainers || uint64(len(rows)) != reported {
		return nil
	}
	out := &DockerInventory{Version: version, Total: total, Running: running, Containers: []DockerContainer{}}
	for _, row := range rows {
		name, status, found := strings.Cut(row, "|")
		status, okStatus := inventoryText(status, 160)
		if !found || !containerNamePattern.MatchString(name) || !okStatus {
			continue
		}
		out.Containers = append(out.Containers, DockerContainer{Name: name, Status: status})
		out.Returned++
	}
	out.Truncated = total > out.Returned
	return out
}
