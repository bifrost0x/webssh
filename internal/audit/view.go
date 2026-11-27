package audit

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
)

// The administrator's audit view (GET /admin/api/audit), read_audit_logs
// of app/audit_logger.py: the newest viewScan lines of the log and its
// rotated files up to the backup count, filtered, then one page.

const (
	viewScan         = 20_000
	viewDefaultLimit = 100
	viewMaxLimit     = 500
)

// ViewQuery is one page request; Offset and Limit are clamped like the
// Python release does (offset at least 0, limit 1 to 500).
type ViewQuery struct {
	Offset, Limit int
	Level         string
	Query         string
}

// View is one page of the audit view. Items are the records as JSON
// objects with sorted keys, as Flask's jsonify wrote them.
type View struct {
	Items  []string
	Total  int
	Offset int
	Limit  int
}

// JSON is the response body {"items":[…],"limit":…,"offset":…,"total":…}.
func (v View) JSON() []byte {
	var b bytes.Buffer
	b.WriteString(`{"items":[`)
	b.WriteString(strings.Join(v.Items, ","))
	fmt.Fprintf(&b, `],"limit":%d,"offset":%d,"total":%d}`, v.Limit, v.Offset, v.Total)
	return b.Bytes()
}

// View reads one page. Only the page is kept in memory; the Python
// release held every scanned line. A line that is not a JSON object is
// skipped, where the Python release listed other JSON values and failed
// on them with a level filter (fix).
func (l *Logger) View(q ViewQuery) (View, error) {
	l.mu.Lock()
	backups := l.opts.BackupCount
	l.mu.Unlock()
	return l.view(q, numbered(l.path, backups), viewScan)
}

func (l *Logger) view(q ViewQuery, files []string, limit int) (View, error) {
	out := View{Offset: max(0, q.Offset), Limit: max(1, min(q.Limit, viewMaxLimit)), Items: []string{}}
	level := ""
	if q.Level != "" {
		level = pyUpper(q.Level)
	}
	query := pyLower([]rune(q.Query))
	_, err := scanFiles(files, limit, func(line []byte) bool {
		if line == nil {
			return true
		}
		text := bytes.TrimSpace(decodeText(line))
		v, err := decodeLine(text)
		if err != nil || v.kind != kindObject {
			return true
		}
		if level != "" && !levelIs(v, level) {
			return true
		}
		if len(query) > 0 && !containsRunes(pyLower([]rune(string(text))), query) {
			return true
		}
		if out.Total >= out.Offset && out.Total < out.Offset+out.Limit {
			var b strings.Builder
			viewJSON.encode(&b, v)
			out.Items = append(out.Items, b.String())
		}
		out.Total++
		return true
	})
	if err != nil {
		return View{}, fmt.Errorf("audit: read logs: %w", err)
	}
	return out, nil
}

// pyInt is int(text) of a query parameter: surrounding whitespace, an
// optional sign, ASCII digits with single underscores between them.
// Values beyond the int range saturate, which the clamping makes
// equivalent.
func pyInt(s string) (int, bool) {
	s = strings.TrimSpace(s)
	neg := false
	if s != "" && (s[0] == '+' || s[0] == '-') {
		neg, s = s[0] == '-', s[1:]
	}
	if s == "" || s[0] == '_' || s[len(s)-1] == '_' || strings.Contains(s, "__") {
		return 0, false
	}
	digitsOnly := strings.ReplaceAll(s, "_", "")
	for _, c := range []byte(digitsOnly) {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	n, err := strconv.ParseInt(digitsOnly, 10, 64)
	if err != nil {
		n = 1 << 62
	}
	if neg {
		n = -n
	}
	return int(n), true
}

// ParseViewQuery reads offset, limit, level and q like admin_audit: when
// either number does not parse, both fall back to 0 and 100.
func ParseViewQuery(offset, limit, level, q string, haveOffset, haveLimit bool) ViewQuery {
	o, l := 0, viewDefaultLimit
	okO, okL := true, true
	if haveOffset {
		o, okO = pyInt(offset)
	}
	if haveLimit {
		l, okL = pyInt(limit)
	}
	if !okO || !okL {
		o, l = 0, viewDefaultLimit
	}
	return ViewQuery{Offset: o, Limit: l, Level: level, Query: q}
}
