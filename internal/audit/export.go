package audit

import "time"

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

// Record is one parsed audit line. Raw keeps the line's JSON object as it
// was written, so an export repeats Python lines byte for byte.
type Record struct {
	Time    time.Time
	Level   Level
	Message string
	Raw     []byte
}
