package hosts

import (
	"errors"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Maintenance is what MaintenanceScript reported (parse_maintenance):
// nil is unknown.
type Maintenance struct {
	RebootRequired  *bool
	Updates         *int
	SecurityUpdates *int
}

// Known reports whether the host reported anything at all; a host
// without the tools keeps its last facts.
func (m Maintenance) Known() bool {
	return m.RebootRequired != nil || m.Updates != nil || m.SecurityUpdates != nil
}

const (
	maxMaintenanceOutput = 1024
	maxPackageCount      = 100000
	maxRebootHintOutput  = 64
)

var (
	errMaintenance = errors.New("hosts: invalid maintenance facts")
	errRebootHint  = errors.New("hosts: invalid restart marker answer")
	packageCount   = regexp.MustCompile(`^[0-9]{1,6}$`)
)

// pySplitLines is str.splitlines(): the line boundaries of Python, with
// CR LF as one, and no empty last line.
func pySplitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch r {
		case '\n', '\r', '\v', '\f', 0x1c, 0x1d, 0x1e, 0x85, 0x2028, 0x2029:
			lines = append(lines, s[start:i])
			if r == '\r' && i+1 < len(s) && s[i+1] == '\n' {
				size++
			}
			start = i + size
		}
		i += size
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

// ParseMaintenance is parse_maintenance.
func ParseMaintenance(text string) (Maintenance, error) {
	if len(text) > maxMaintenanceOutput || !utf8.ValidString(text) ||
		strings.ContainsFunc(text, func(r rune) bool { return r < 32 && r != '\n' && r != '\r' && r != '\t' }) {
		return Maintenance{}, errMaintenance
	}
	facts := map[string]string{}
	for _, line := range pySplitLines(text) {
		key, value, found := strings.Cut(line, "=")
		if _, seen := facts[key]; found && !seen {
			facts[key] = pyStrip(value)
		}
	}
	count := func(value string, present bool) *int {
		if !present || !packageCount.MatchString(value) {
			return nil
		}
		n := 0
		for _, c := range value {
			n = n*10 + int(c-'0')
		}
		if n > maxPackageCount {
			return nil
		}
		return &n
	}
	var m Maintenance
	switch facts["reboot"] {
	case "yes":
		m.RebootRequired = new(true)
	case "no":
		m.RebootRequired = new(false)
	}
	if apt, ok := facts["apt"]; ok {
		security, has := facts["aptsecurity"]
		m.Updates, m.SecurityUpdates = count(apt, true), count(security, has)
	}
	if m.Updates != nil && m.SecurityUpdates != nil && *m.SecurityUpdates > *m.Updates {
		m.SecurityUpdates = new(*m.Updates)
	}
	return m, nil
}

// ParseRebootHint accepts exactly the one line RebootHintScript prints;
// banners or extra lines are not an answer.
func ParseRebootHint(text string) (bool, error) {
	if len(text) > maxRebootHintOutput || !utf8.ValidString(text) {
		return false, errRebootHint
	}
	switch pyStrip(text) {
	case "reboot=yes":
		return true, nil
	case "reboot=no":
		return false, nil
	}
	return false, errRebootHint
}
