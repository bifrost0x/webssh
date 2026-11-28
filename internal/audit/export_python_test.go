package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/oracletest"
)

// pythonAudit runs app/audit_export.py and read_audit_logs on dataDir.
const pythonAudit = `
import json, sys
from app import audit_export as a
from app.audit_logger import read_audit_logs
spec = json.load(sys.stdin)
out = {"export": [], "view": [], "times": []}
for c in spec["export"]:
    start = a._parse_timestamp(c.get("from"))
    end = a._parse_timestamp(c.get("to"))
    meta = a.audit_scan_metadata(a.AUDIT_LOG_FILE, max_scan=c["max"])
    text = json.dumps({"type": "webssh_audit_export", **meta}, separators=(",", ":")) + "\n"
    for r in a.iter_audit_records(a.AUDIT_LOG_FILE, start=start, end=end, level=c.get("level"), query=c.get("q"), max_scan=c["max"]):
        text += json.dumps(r, ensure_ascii=False, separators=(",", ":")) + "\n"
    out["export"].append(text)
for c in spec["view"]:
    r = read_audit_logs(offset=c["offset"], limit=c["limit"], level=c.get("level"), q=c.get("q"), max_scan=c["max"])
    out["view"].append(json.dumps(r, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
for s in spec["times"]:
    try:
        out["times"].append(a._parse_timestamp(s).isoformat())
    except (TypeError, ValueError):
        out["times"].append(None)
sys.stdout.write("\n--result--\n" + json.dumps(out))
`

type exportCase struct {
	From  string `json:"from,omitempty"`
	To    string `json:"to,omitempty"`
	Level string `json:"level,omitempty"`
	Q     string `json:"q,omitempty"`
	Max   int    `json:"max"`
}

type viewCase struct {
	Offset int    `json:"offset"`
	Limit  int    `json:"limit"`
	Level  string `json:"level,omitempty"`
	Q      string `json:"q,omitempty"`
	Max    int    `json:"max"`
}

var handLines = []string{
	`{"timestamp": "2026-11-03T10:00:00+01:00", "level": "warning", "logger": "x", "message": "Größe İstanbul ΣΑΣ"}`,
	`{"timestamp":"2026-11-03T11:00:00Z","level":"INFO","n":[1E5,-0,1.10,123456789012345678901234567890,1e-7,1e16,12345678901234567.0,0.0001,-2.5e-300],"o":{"a":null,"b":true,"c":{}},"dup":1,"dup":2}`,
	`{"timestamp":"2026-11-03T11:30:00.5Z","level":"ERROR","message":"\u00e9\ud83d\ude00\t\u0001\u007f \"q\" \\ /"}`,
	"not json at all",
	"",
	`{"level": "INFO", "message": "no timestamp"}`,
	`{"timestamp": "", "level": "INFO", "message": "empty timestamp"}`,
	`{"timestamp": "yesterday", "level": "INFO", "message": "bad timestamp"}`,
	`{"timestamp": "20261103T120000", "level": 5, "message": "basic format, numeric level"}`,
	`{"timestamp": "2026-11-03 12:30", "message": "no level"}`,
	"{\"timestamp\":\"2026-11-03T13:00:00Z\",\"level\":\"INFO\",\"message\":\"bad \xff\xe2\x82 x\xed\xa0\x80y\"}",
	`{"timestamp": "2026-11-03T14:00:00Z", "level": "INFO", "message": "crlf"}` + "\r",
	`  {"timestamp": "2026-11-03T15:00:00Z", "level": "Warning", "message": "padded ADMIN"}  `,
}

// auditDir writes a mixed log directory: Go lines and hand-written lines
// in the log, the Python fixture in .1, more lines in .2 and a file with
// a non-numeric suffix (read by the export only) holding NaN.
func auditDir(t *testing.T) (string, *Logger) {
	t.Helper()
	data := t.TempDir()
	logs := filepath.Join(data, "logs")
	clock := time.Date(2026, 11, 4, 8, 0, 0, 0, time.UTC)
	l, err := Open(logs, Options{BackupCount: 5, Now: func() time.Time { clock = clock.Add(1500 * time.Microsecond); return clock }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	py, err := os.ReadFile("testdata/python_security_audit.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	write := func(name, text string) {
		if err := os.WriteFile(filepath.Join(logs, name), []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(FileName+".1", string(py))
	write(FileName+".2", strings.Join(handLines[6:], "\n")+"\n")
	write(FileName+".bak", `{"timestamp":"2026-11-01T00:00:00Z","level":"INFO","v":NaN,"w":[Infinity,-Infinity]}`+"\n[1, 2, 3]\n")
	write(FileName, strings.Join(handLines[:6], "\n")+"\n")
	l.Event(Info, "LOGIN_SUCCESS", F("user", "Ådmin"), F("ip", "203.0.113.9"))
	l.Event(Warning, "ADMIN_CONNECTION_DISCONNECT", F("admin_id", 1), F("outcome", "disconnected"))
	l.Event(Info, "AUDIT_EXPORT", F("admin", "golden_admin"))
	return data, l
}

// logDigests is the SHA-256 of every file of the log directory the Python
// release reads, so that the recorded answers belong to these inputs.
func logDigests(t *testing.T, dir string) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, e := range entries {
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(raw)
		out[e.Name()] = hex.EncodeToString(sum[:])
	}
	return out
}

// The export and the view of the log match app/audit_export.py and
// read_audit_logs; the Python answers are recorded in
// testdata/python_audit_export.json.
func TestExportAndViewMatchPython(t *testing.T) {
	data, l := auditDir(t)
	exports := []exportCase{
		{Max: MaxExportScan},
		{Level: "warning", Max: MaxExportScan},
		{Level: "INFO", Max: MaxExportScan},
		{Level: "5", Max: MaxExportScan},
		{Q: "GRÖSSE", Max: MaxExportScan},
		{Q: "größe", Max: MaxExportScan},
		{Q: "i̇stanbul", Max: MaxExportScan},
		{Q: "σας", Max: MaxExportScan},
		{Q: "golden_admin", Max: MaxExportScan},
		{Q: `"dup":2`, Max: MaxExportScan},
		{Q: `"dup": 2`, Max: MaxExportScan},
		{From: "2026-11-03T11:00:00Z", Max: MaxExportScan},
		{From: "2026-11-02", To: "2026-11-03T12:00:00+00:00", Max: MaxExportScan},
		{To: "2026-11-02T09:00:09.25", Max: MaxExportScan},
		{Max: 7},
		{Max: 3, Level: "INFO"},
		{Max: 1000, Q: "fffd"},
	}
	views := []viewCase{
		{Offset: 0, Limit: 100, Max: viewScan},
		{Offset: 2, Limit: 3, Level: "info", Max: viewScan},
		{Offset: 0, Limit: 1, Q: "GOLDEN", Max: viewScan},
		{Offset: 0, Limit: 100, Q: "admin", Max: viewScan},
		{Offset: 1000, Limit: 5, Max: viewScan},
		{Offset: -5, Limit: 0, Max: viewScan},
		{Offset: 0, Limit: 600, Max: 5},
		{Offset: 0, Limit: 50, Level: "5", Max: viewScan},
	}
	times := []string{"2026-11-02T09:00:00Z", "2026-11-02T09:00:00.250000Z", "2026-11-02T09:00:00.1234567+01:30",
		"20261102T090000", "2026-11-02 09", "2026-11-02X09:00", "2026-11-02", "2026-11-02T09:00:00,5",
		"2026-11-02T09:00+0130", "2026-11-02T24:00:00", "2026-02-30", "2026-11-02T25:00", "x", "2026-11-02T",
		"2026-11-02T09:00:00-05", "2026-11-02T09:00:00+00:00:30", "2026-11-02T0900", "2026-11-02T09:00:60"}
	type answer struct {
		Export []string  `json:"export"`
		View   []string  `json:"view"`
		Times  []*string `json:"times"`
	}
	spec := map[string]any{"export": exports, "view": views, "times": times}
	request := map[string]any{"spec": spec, "logs": logDigests(t, filepath.Join(data, "logs"))}
	rec := oracletest.Open(t, "testdata/python_audit_export.json")
	want := oracletest.Ask(t, rec, "export_and_view", request, func(r oracletest.Release) answer {
		in, err := json.Marshal(spec)
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.CommandContext(t.Context(), r.Python, "-c", pythonAudit) // #nosec G204 -- test oracle
		cmd.Dir = r.Root
		cmd.Env = append(os.Environ(), "DATA_DIR="+data, "SECRET_KEY=differential-test-only-0123456789abcdef", "PYTHONDONTWRITEBYTECODE=1")
		cmd.Stdin = bytes.NewReader(in)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		raw, err := cmd.Output()
		if err != nil {
			t.Fatalf("python: %v\n%s", err, stderr.String())
		}
		var a answer
		_, raw, _ = bytes.Cut(raw, []byte("\n--result--\n"))
		if err := json.Unmarshal(raw, &a); err != nil {
			t.Fatal(err)
		}
		return a
	})
	for i, c := range exports {
		got := goExport(t, l, c)
		if got != want.Export[i] {
			t.Errorf("export %+v:\n got %s\nwant %s", c, got, want.Export[i])
		}
	}
	for i, c := range views {
		v, err := l.view(ViewQuery{Offset: c.Offset, Limit: c.Limit, Level: c.Level, Query: c.Q}, numbered(l.path, 5), c.Max)
		if err != nil {
			t.Fatal(err)
		}
		if got := string(v.JSON()); got != want.View[i] {
			t.Errorf("view %+v:\n got %s\nwant %s", c, got, want.View[i])
		}
	}
	for i, s := range times {
		got, err := parseTimestamp(s)
		switch w := want.Times[i]; {
		case w == nil && err == nil:
			t.Errorf("time %q: Go accepts %v, Python refuses", s, got)
		case w != nil && err != nil:
			t.Errorf("time %q: Go refuses, Python %s", s, *w)
		case w != nil:
			pt, perr := time.Parse("2006-01-02T15:04:05.999999-07:00", *w)
			if perr != nil {
				pt, perr = time.Parse("2006-01-02T15:04:05.999999", *w)
			}
			if perr != nil || !pt.UTC().Equal(got) {
				t.Errorf("time %q: Go %v, Python %s", s, got, *w)
			}
		}
	}
}

func goExport(t *testing.T, l *Logger, c exportCase) string {
	t.Helper()
	var f ExportFilter
	var ok bool
	if f.From, ok = timestampParam(c.From); !ok {
		t.Fatalf("from %q", c.From)
	}
	if f.To, ok = timestampParam(c.To); !ok {
		t.Fatalf("to %q", c.To)
	}
	f.Level, f.Query = Level(c.Level), c.Q
	meta, err := l.exportScan(c.Max)
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	b.WriteString(meta.line(c.Max))
	if err := l.export(&b, f, c.Max); err != nil {
		t.Fatal(err)
	}
	return b.String()
}
