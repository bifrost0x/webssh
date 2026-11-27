package hostops

import (
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Process is one row of process.list.
type Process struct {
	PID     int    `json:"pid"`
	User    string `json:"user"`
	CPU     string `json:"cpu"`
	Memory  string `json:"memory"`
	Command string `json:"command"`
}

var (
	psPID     = regexp.MustCompile(`^[0-9]{1,7}$`)
	psPercent = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+)?$`)
)

// parseProcessList is parse_process_list: a complete ps snapshot; one
// malformed or repeated row fails the whole list instead of being left
// out silently.
func parseProcessList(output string) ([]Process, error) {
	rows := []Process{}
	seen := map[int]bool{}
	for _, line := range splitLines(output) {
		if pyStrip(line) == "" {
			continue
		}
		f := splitFields(line, 4)
		if len(f) != 5 || !psPID.MatchString(f[0]) {
			return nil, opErr("invalid_output")
		}
		pid, _ := strconv.Atoi(f[0])
		if pid < 1 || pid > maxPID || seen[pid] || !psPercent.MatchString(f[2]) || !psPercent.MatchString(f[3]) {
			return nil, opErr("invalid_output")
		}
		seen[pid] = true
		rows = append(rows, Process{PID: pid, User: f[1], CPU: f[2], Memory: f[3], Command: f[4]})
	}
	return rows, nil
}

// logRecord is the lines of one timestamp of docker logs.
type logRecord struct {
	key   string
	lines []string
}

// dockerTimestamp matches the RFC 3339 timestamp docker logs --timestamps
// writes before a line, followed by white space; it returns the stamp.
// Python's \d and \s match Unicode digits and white space, so these do.
func dockerTimestamp(line string) (string, bool) {
	const layout = "dddd-dd-ddTdd:dd:dd.dddddddddZ"
	i := 0
	for _, want := range layout {
		r, size := utf8.DecodeRuneInString(line[i:])
		if size == 0 {
			return "", false
		}
		ok := r == want
		if want == 'd' {
			ok = unicode.Is(unicode.Nd, r)
		}
		if !ok {
			return "", false
		}
		i += size
	}
	r, size := utf8.DecodeRuneInString(line[i:])
	if size == 0 || !pyIsSpace(r) {
		return "", false
	}
	return line[:i], true
}

// newestContainerLogs is newest_container_logs: the timestamped records
// of both streams, newest first, with continuation lines kept under their
// record; lines before the first timestamp are returned apart.
func newestContainerLogs(output, errOutput string) (string, string) {
	var records []*logRecord
	var unstructured []string
	for _, stream := range []string{output, errOutput} {
		var current *logRecord
		for _, line := range splitLines(stream) {
			key, stamped := dockerTimestamp(line)
			switch {
			case stamped:
				if current == nil || current.key != key {
					current = &logRecord{key: key}
					records = append(records, current)
				}
				current.lines = append(current.lines, line)
			case current != nil:
				current.lines = append(current.lines, line)
			default:
				unstructured = append(unstructured, line)
			}
		}
	}
	slices.SortStableFunc(records, func(a, b *logRecord) int { return strings.Compare(b.key, a.key) })
	var lines []string
	for _, r := range records {
		lines = append(lines, r.lines...)
	}
	return strings.Join(lines, "\n"), strings.Join(unstructured, "\n")
}
