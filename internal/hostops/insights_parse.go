package hostops

import (
	"errors"
	"math"
	"slices"
	"strings"
	"unicode/utf8"
)

// Limits of a session insights sample (app/session_insights.py).
const (
	insightsMaxBytes = 16 << 10
	maxInt63         = math.MaxInt64
)

var errNoMetrics = errors.New("hostops: no supported metrics")

// Stats is one parsed sample of session insights. Every section is
// present only when its values were complete and consistent; the texts
// are bounded and free of control characters.
type Stats struct {
	CPU              []uint64      `json:"cpu,omitempty"`
	Memory           *MemoryStats  `json:"memory,omitempty"`
	Disk             *DiskStats    `json:"disk,omitempty"`
	UptimeSeconds    *uint64       `json:"uptime_seconds,omitempty"`
	OSName           string        `json:"os_name,omitempty"`
	Load             *LoadStats    `json:"load,omitempty"`
	Swap             *MemoryStats  `json:"swap,omitempty"`
	Network          *NetworkStats `json:"network,omitempty"`
	Processes        *ProcessStats `json:"processes,omitempty"`
	PermissionDenied []string      `json:"permission_denied,omitempty"`
}

// MemoryStats is memory or swap in KiB.
type MemoryStats struct {
	TotalKiB     uint64 `json:"total_kib"`
	AvailableKiB uint64 `json:"available_kib"`
	UsedKiB      uint64 `json:"used_kib"`
}

// DiskStats is the root file system in KiB.
type DiskStats struct {
	TotalKiB     uint64 `json:"total_kib"`
	UsedKiB      uint64 `json:"used_kib"`
	AvailableKiB uint64 `json:"available_kib"`
	Percent      uint64 `json:"percent"`
}

// LoadStats is the load average with the number of CPUs.
type LoadStats struct {
	One      float64 `json:"one"`
	Five     float64 `json:"five"`
	Fifteen  float64 `json:"fifteen"`
	CPUCount uint64  `json:"cpu_count"`
}

// NetworkStats are the byte counters of every interface but lo.
type NetworkStats struct {
	ReceivedBytes    uint64 `json:"received_bytes"`
	TransmittedBytes uint64 `json:"transmitted_bytes"`
}

// ProcessStats counts processes and lists the top five by CPU and memory.
type ProcessStats struct {
	Total     uint64       `json:"total"`
	Zombies   uint64       `json:"zombies"`
	TopCPU    []TopProcess `json:"top_cpu"`
	TopMemory []TopProcess `json:"top_memory"`
}

// TopProcess is one row of a top list.
type TopProcess struct {
	PID           uint64  `json:"pid"`
	User          string  `json:"user"`
	Command       string  `json:"command"`
	CPUPercent    float64 `json:"cpu_percent"`
	MemoryPercent float64 `json:"memory_percent"`
}

var insightsSingleKeys = map[string]bool{
	"cpu": true, "mem_total_kib": true, "mem_available_kib": true,
	"disk_total_kib": true, "disk_used_kib": true, "disk_available_kib": true,
	"disk_percent": true, "uptime_seconds": true, "os_name": true,
	"load_1": true, "load_5": true, "load_15": true, "cpu_count": true,
	"swap_total_kib": true, "swap_free_kib": true,
	"network_received_bytes": true, "network_transmitted_bytes": true,
	"process_total": true, "process_zombies": true,
}

var insightsMultiKeys = map[string]bool{"process_cpu": true, "process_memory": true, "permission_denied": true}

// insightsText is _safe_text of session_insights: stripped, 1 to max
// characters, no control characters.
func insightsText(v string, max int) (string, bool) {
	v = pyStrip(v)
	if v == "" || runeLen(v) > max || hasControl(v) {
		return "", false
	}
	return v, true
}

// ParseStats parses the output of the fixed collector
// (parse_linux_stats). It fails when the output is too large or carries
// no supported metric.
func ParseStats(text string) (Stats, error) {
	if len(text) > insightsMaxBytes {
		return Stats{}, errors.New("hostops: stats payload too large")
	}
	if !utf8.ValidString(text) {
		return Stats{}, errors.New("hostops: stats payload is not UTF-8")
	}
	values := map[string]string{}
	repeated := map[string][]string{}
	for _, line := range splitLines(text) {
		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		switch {
		case insightsSingleKeys[key]:
			values[key] = pyStrip(value)
		case insightsMultiKeys[key] && len(repeated[key]) < 16:
			repeated[key] = append(repeated[key], pyStrip(value))
		}
	}
	count := func(key string, limit uint64) (uint64, bool) {
		v, ok := values[key]
		if !ok {
			return 0, false
		}
		return parseCount(v, limit)
	}
	float := func(key string, limit float64) (float64, bool) {
		v, ok := values[key]
		if !ok {
			return 0, false
		}
		return parseFloat(v, limit)
	}
	var st Stats
	st.CPU = parseCPU(values["cpu"])

	if total, ok := count("mem_total_kib", maxInt63); ok {
		if avail, ok := count("mem_available_kib", maxInt63); ok && total > 0 && avail <= total {
			st.Memory = &MemoryStats{TotalKiB: total, AvailableKiB: avail, UsedKiB: total - avail}
		}
	}
	total, okT := count("disk_total_kib", maxInt63)
	used, okU := count("disk_used_kib", maxInt63)
	avail, okA := count("disk_available_kib", maxInt63)
	percent, okP := count("disk_percent", 100)
	if okT && okU && okA && okP && total > 0 && used <= total && avail <= total {
		st.Disk = &DiskStats{TotalKiB: total, UsedKiB: used, AvailableKiB: avail, Percent: percent}
	}
	if up, ok := float("uptime_seconds", maxInt63); ok {
		u := uint64(up)
		st.UptimeSeconds = &u
	}
	if name, ok := values["os_name"]; ok {
		st.OSName, _ = insightsText(name, 200)
	}
	l1, ok1 := float("load_1", 1_000_000)
	l5, ok5 := float("load_5", 1_000_000)
	l15, ok15 := float("load_15", 1_000_000)
	if cpus, ok := count("cpu_count", 1_000_000); ok1 && ok5 && ok15 && ok && cpus > 0 {
		st.Load = &LoadStats{One: l1, Five: l5, Fifteen: l15, CPUCount: cpus}
	}
	if total, ok := count("swap_total_kib", maxInt63); ok {
		if free, ok := count("swap_free_kib", maxInt63); ok && free <= total {
			st.Swap = &MemoryStats{TotalKiB: total, AvailableKiB: free, UsedKiB: total - free}
		}
	}
	if rx, ok := count("network_received_bytes", math.MaxUint64); ok {
		if tx, ok := count("network_transmitted_bytes", math.MaxUint64); ok {
			st.Network = &NetworkStats{ReceivedBytes: rx, TransmittedBytes: tx}
		}
	}
	procs, okProcs := count("process_total", 10_000_000)
	zombies, okZombies := count("process_zombies", 10_000_000)
	topCPU := parseTopProcesses(repeated["process_cpu"])
	topMem := parseTopProcesses(repeated["process_memory"])
	if okProcs && okZombies && zombies <= procs && (len(topCPU) > 0 || len(topMem) > 0) {
		st.Processes = &ProcessStats{Total: procs, Zombies: zombies, TopCPU: topCPU, TopMemory: topMem}
	}
	for _, scope := range repeated["permission_denied"] {
		if scope == "processes" && !slices.Contains(st.PermissionDenied, scope) {
			st.PermissionDenied = append(st.PermissionDenied, scope)
		}
	}
	if st.empty() {
		return Stats{}, errNoMetrics
	}
	return st, nil
}

func (s *Stats) empty() bool {
	return s.CPU == nil && s.Memory == nil && s.Disk == nil && s.UptimeSeconds == nil && s.OSName == "" &&
		s.Load == nil && s.Swap == nil && s.Network == nil && s.Processes == nil && s.PermissionDenied == nil
}

// parseCPU is the cpu line of /proc/stat: at least four counters.
func parseCPU(line string) []uint64 {
	fields := splitFields(line, -1)
	if len(fields) < 4 {
		return nil
	}
	out := make([]uint64, 0, len(fields))
	for _, f := range fields {
		v, ok := parseCount(f, math.MaxUint64)
		if !ok {
			return nil
		}
		out = append(out, v)
	}
	return out
}

// parseTopProcesses is _parse_process_rows: the first five rows, each
// "pid|user|command|cpu|mem"; malformed rows are skipped.
func parseTopProcesses(rows []string) []TopProcess {
	out := []TopProcess{}
	for _, row := range rows[:min(len(rows), 5)] {
		parts := strings.Split(row, "|")
		if len(parts) != 5 {
			continue
		}
		pid, okPID := parseCount(parts[0], math.MaxInt32)
		user, okUser := insightsText(parts[1], 64)
		command, okCmd := insightsText(parts[2], 128)
		cpu, okCPU := parseFloat(parts[3], 100_000)
		mem, okMem := parseFloat(parts[4], 100)
		if !okPID || !okUser || !okCmd || !okCPU || !okMem || pid == 0 {
			continue
		}
		out = append(out, TopProcess{PID: pid, User: user, Command: command, CPUPercent: cpu, MemoryPercent: mem})
	}
	return out
}
