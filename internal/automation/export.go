package automation

import (
	"bytes"
	"strings"
)

// ExportJSON is the JSON export: json.dumps(run, ensure_ascii=True).
func ExportJSON(r Run) []byte { return []byte(pyDump(r.Value(), dumpOptions{})) }

// csvHeader is the header row of the CSV export.
var csvHeader = []string{"run_id", "workflow", "created_at", "finished_at", "run_status",
	"target_id", "target", "host", "port", "username", "group", "target_status", "target_reason",
	"step", "status", "reason", "exit_code", "duration", "output_truncated", "stdout", "stderr"}

// ExportCSV is the CSV export: one row per step, written as Python's
// csv.writer does, with values that a spreadsheet would read as a
// formula prefixed by an apostrophe.
func ExportCSV(r Run) []byte {
	var b bytes.Buffer
	writeRow(&b, csvHeader)
	opt := func(s *string) string {
		if s == nil {
			return ""
		}
		return *s
	}
	for _, t := range r.Targets {
		for _, st := range t.Steps {
			exit, truncated, stdout, stderr := "", "", "", ""
			if st.ExitCode != nil {
				exit = itoa(*st.ExitCode)
			}
			if st.Detailed {
				truncated = "False"
				if st.Truncated {
					truncated = "True"
				}
				stdout, stderr = st.Stdout, st.Stderr
			}
			finished := ""
			if r.Finished {
				finished = opt(r.FinishedAt)
			}
			row := []string{r.ID, r.Name, r.CreatedAt, finished, r.Status,
				t.ID, t.Name, t.Host, itoa(t.Port), t.Username, opt(t.Group),
				t.Status, opt(t.Reason), st.Name, st.Status, opt(st.Reason),
				exit, st.Duration, truncated, stdout, stderr}
			for i := range row {
				row[i] = spreadsheetSafe(row[i])
			}
			writeRow(&b, row)
		}
	}
	return b.Bytes()
}

// spreadsheetSafe is safe() of the export route.
func spreadsheetSafe(v string) string {
	trimmed := strings.TrimLeft(v, "\ufeff \t\r\n\v\f")
	if strings.HasPrefix(trimmed, "=") || strings.HasPrefix(trimmed, "+") || strings.HasPrefix(trimmed, "-") ||
		strings.HasPrefix(trimmed, "@") || strings.HasPrefix(v, "\t") || strings.HasPrefix(v, "\r") || strings.HasPrefix(v, "\n") {
		return "'" + v
	}
	return v
}

// writeRow writes one row as csv.writer with the excel dialect: fields
// with a delimiter, quote or line break are quoted, quotes doubled,
// rows end in CRLF.
func writeRow(b *bytes.Buffer, fields []string) {
	for i, f := range fields {
		if i > 0 {
			b.WriteByte(',')
		}
		if strings.ContainsAny(f, ",\"\r\n") || (len(fields) == 1 && f == "") {
			b.WriteByte('"')
			b.WriteString(strings.ReplaceAll(f, `"`, `""`))
			b.WriteByte('"')
		} else {
			b.WriteString(f)
		}
	}
	b.WriteString("\r\n")
}
