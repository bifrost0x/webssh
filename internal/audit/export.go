package audit

import (
	"fmt"
	"io"
	"strings"
	"time"
)

// The audit view and export (C-AOPS-01 to -04, docs/architecture/
// m2-contracts.md). The export reads security_audit.log and its rotated
// files, newest last, Python and Go lines alike (E34, invariant I-10); it
// is streamed as NDJSON with a first metadata line, as audit_export.py
// writes it.

// MaxExportScan bounds the lines one export or view reads
// (MAX_EXPORT_SCAN); a scan that stops there is marked truncated.
const MaxExportScan = 50_000

// Retention is the number of rotated audit files that are kept
// (backup_count 1 to MaxBackupCount, POST /admin/api/audit/retention); the
// rotation applies it (Logger.SetBackupCount), so no retention job exists.

// ExportFilter selects the records of an export; zero fields select all.
// From and To compare with the record's timestamp; Query is a substring
// of the message, matched as the Python release matches it.
type ExportFilter struct {
	From, To time.Time
	Level    Level
	Query    string
}

// ExportMeta is the first line of an export and the X-WebSSH-Audit-*
// headers: {"type":"webssh_audit_export","scanned":…,"truncated":…}.
type ExportMeta struct {
	Scanned   int
	Truncated bool
}

// Completeness is the X-WebSSH-Audit-Completeness header.
func (m ExportMeta) Completeness() string {
	if m.Truncated {
		return "truncated"
	}
	return "complete-within-retained-logs"
}

// Record is one parsed audit line; Raw is the line as read. The export
// writes the Python round trip of the line, which is what the Python
// release streamed (see Logger.Export).
type Record struct {
	Time    time.Time
	Level   Level
	Message string
	Raw     []byte
}

// Export writes the records that match f, newest first, as audit_export.py
// streams them: one compact JSON line per record (json.dumps with
// ensure_ascii=False). The caller writes the metadata line and headers
// first from ExportScan, as the Python release counts before it reads.
func (l *Logger) Export(w io.Writer, f ExportFilter) error {
	return l.export(w, f, MaxExportScan)
}

// ExportScan counts the lines an export reads, at most MaxExportScan.
func (l *Logger) ExportScan() (ExportMeta, error) { return l.exportScan(MaxExportScan) }

func (l *Logger) exportScan(limit int) (ExportMeta, error) {
	files, err := candidateFiles(l.path)
	if err != nil {
		return ExportMeta{}, fmt.Errorf("audit: list logs: %w", err)
	}
	var m ExportMeta
	m.Truncated, err = scanFiles(files, limit, func([]byte) bool { m.Scanned++; return true })
	if err != nil {
		return ExportMeta{}, fmt.Errorf("audit: read logs: %w", err)
	}
	return m, nil
}

func (l *Logger) export(w io.Writer, f ExportFilter, limit int) error {
	files, err := candidateFiles(l.path)
	if err != nil {
		return fmt.Errorf("audit: list logs: %w", err)
	}
	level := pyUpper(string(f.Level))
	query := pyLower([]rune(f.Query))
	var werr error
	_, err = scanFiles(files, limit, func(line []byte) bool {
		rec, ok := parseRecord(line)
		if !ok || !f.matches(rec, level, query) {
			return true
		}
		var b strings.Builder
		exportLine.encode(&b, rec.v)
		b.WriteByte('\n')
		_, werr = io.WriteString(w, b.String())
		return werr == nil
	})
	if werr != nil {
		return werr
	}
	if err != nil {
		return fmt.Errorf("audit: read logs: %w", err)
	}
	return nil
}

// record is one line read back, with its timestamp when it has one.
type record struct {
	v      value
	ts     time.Time
	hasTS  bool
	stored []byte
}

// parseRecord is the per-line part of iter_audit_records: a JSON object
// whose timestamp is missing, empty or ISO 8601. A record with another
// timestamp is skipped; the Python release failed the export on a
// non-string timestamp (fix).
func parseRecord(line []byte) (record, bool) {
	if line == nil {
		return record{}, false
	}
	text := decodeText(line)
	v, err := decodeLine(text)
	if err != nil || v.kind != kindObject {
		return record{}, false
	}
	rec := record{v: v, stored: text}
	ts, ok := v.member("timestamp")
	if !ok || falsy(ts) {
		return rec, true
	}
	if ts.kind != kindString {
		return record{}, false
	}
	t, err := parseTimestamp(string(ts.str))
	if err != nil {
		return record{}, false
	}
	rec.ts, rec.hasTS = t, true
	return rec, true
}

// falsy is Python's "not value".
func falsy(v value) bool {
	switch v.kind {
	case kindNull:
		return true
	case kindBool:
		return !v.b
	case kindInt:
		return v.num == "0"
	case kindFloat:
		return v.f == 0
	case kindString:
		return len(v.str) == 0
	case kindArray:
		return len(v.items) == 0
	}
	return len(v.keys) == 0
}

func (f ExportFilter) matches(r record, level string, query []rune) bool {
	if !f.From.IsZero() && (!r.hasTS || r.ts.Before(f.From)) {
		return false
	}
	if !f.To.IsZero() && (!r.hasTS || r.ts.After(f.To)) {
		return false
	}
	if level != "" && !levelIs(r.v, level) {
		return false
	}
	if len(query) > 0 {
		var b strings.Builder
		queryText.encode(&b, r.v)
		if !containsRunes(pyLower([]rune(b.String())), query) {
			return false
		}
	}
	return true
}

// levelIs is str(record.get("level", "")).upper() == level.
func levelIs(v value, level string) bool {
	lv, ok := v.member("level")
	if !ok {
		return level == ""
	}
	s, ok := pyStrOf(lv)
	return ok && pyUpper(s) == level
}
