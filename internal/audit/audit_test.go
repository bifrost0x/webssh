package audit

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal/principaltest"
)

type pyCase struct {
	Event   string           `json:"event"`
	Fields  []jsontext.Value `json:"fields"`
	Message string           `json:"message"`
	Line    string           `json:"line"`
}

func loadCases(t *testing.T) []pyCase {
	t.Helper()
	raw, err := os.ReadFile("testdata/python_events.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []pyCase
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	return cases
}

func fieldsOf(t *testing.T, raw []jsontext.Value) []Field {
	t.Helper()
	var out []Field
	for _, r := range raw {
		var pair []any
		if err := json.Unmarshal(r, &pair); err != nil {
			t.Fatal(err)
		}
		v := pair[1]
		if f, ok := v.(float64); ok {
			v = int64(f)
		}
		out = append(out, F(pair[0].(string), v))
	}
	return out
}

// The message and the whole line equal what the Python release writes
// for the same event and fields.
func TestEventMatchesPython(t *testing.T) {
	t.Parallel()
	fixed := func() time.Time { return time.Date(2026, 11, 2, 9, 0, 0, 0, time.UTC) }
	for _, c := range loadCases(t) {
		fields := fieldsOf(t, c.Fields)
		if got := eventMessage(c.Event, fields); got != c.Message {
			t.Errorf("%s:\n got %q\nwant %q", c.Event, got, c.Message)
		}
		l := &Logger{opts: Options{Now: fixed}}
		if got := strings.TrimSuffix(l.line(Info, c.Message), "\n"); got != c.Line {
			t.Errorf("%s line:\n got %s\nwant %s", c.Event, got, c.Line)
		}
	}
}

// Lines written by the Python release (golden fixture) are reproduced
// byte for byte from their timestamp and message.
func TestGoldenLinesRoundTrip(t *testing.T) {
	t.Parallel()
	f, err := os.Open("testdata/python_security_audit.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	n := 0
	for sc.Scan() {
		var rec struct {
			Timestamp string `json:"timestamp"`
			Level     string `json:"level"`
			Logger    string `json:"logger"`
			Message   string `json:"message"`
		}
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			t.Fatal(err)
		}
		ts, err := time.Parse(time.RFC3339Nano, rec.Timestamp)
		if err != nil {
			t.Fatal(err)
		}
		l := &Logger{opts: Options{Now: func() time.Time { return ts }}}
		if got := strings.TrimSuffix(l.line(Level(rec.Level), rec.Message), "\n"); got != sc.Text() {
			t.Errorf("line %d:\n got %s\nwant %s", n, got, sc.Text())
		}
		n++
	}
	if n == 0 {
		t.Fatal("empty golden log")
	}
}

func TestTimestamp(t *testing.T) {
	t.Parallel()
	for in, want := range map[time.Time]string{
		time.Date(2026, 11, 2, 9, 0, 0, 0, time.UTC):         "2026-11-02T09:00:00Z",
		time.Date(2026, 11, 2, 9, 0, 9, 250000000, time.UTC): "2026-11-02T09:00:09.250000Z",
		time.Date(2026, 11, 2, 9, 0, 9, 999, time.UTC):       "2026-11-02T09:00:09Z",
	} {
		if got := timestamp(in); got != want {
			t.Errorf("%v: %s, want %s", in, got, want)
		}
	}
}

func TestLegacyMessages(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	var console bytes.Buffer
	l, err := Open(dir, Options{BackupCount: 3, Console: &console})
	if err != nil {
		t.Fatal(err)
	}
	l.LoginAttempt("a|b\n", false, "10.0.0.1", "UA")
	l.Logout("a", "::1")
	l.Registration("a", true, "ip")
	l.PasswordChange("a", true, "ip")
	l.RateLimitExceeded("login", "ip", "")
	l.RateLimitExceeded("login_username", "ip", "bob")
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, FileName))
	want := []string{
		`LOGIN_FAILED | user=a\\|b\\n | ip=10.0.0.1 | user_agent=UA`,
		`LOGOUT | user=a | ip=::1`,
		`REGISTRATION_SUCCESS | user=a | ip=ip`,
		`PASSWORD_CHANGE_SUCCESS | user=a | ip=ip`,
		`"level": "WARNING", "logger": "security_audit", "message": "RATE_LIMIT_EXCEEDED | endpoint=login | ip=ip"`,
		`RATE_LIMIT_EXCEEDED | endpoint=login_username | ip=ip | user=bob`,
	}
	for _, w := range want {
		if !strings.Contains(string(raw), w) {
			t.Errorf("log lacks %s\n%s", w, raw)
		}
	}
	if console.String() != string(raw) {
		t.Error("console copy differs from the file")
	}
	if info, _ := os.Stat(filepath.Join(dir, FileName)); info.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", info.Mode().Perm())
	}
}

// Rotation follows RotatingFileHandler: never an empty file, rotate when
// the next line would reach the limit, keep BackupCount files.
func TestRotation(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	// Files beyond the count and look-alikes: only numbered ones above
	// the count are removed at open.
	for _, name := range []string{FileName + ".7", FileName + ".2", FileName + ".x", FileName + ".1.gz"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("old\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	fixed := func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }
	l, err := Open(dir, Options{MaxBytes: 200, BackupCount: 2, Now: fixed})
	if err != nil {
		t.Fatal(err)
	}
	for _, gone := range []string{FileName + ".7"} {
		if _, err := os.Stat(filepath.Join(dir, gone)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s not pruned", gone)
		}
	}
	for _, kept := range []string{FileName + ".2", FileName + ".x", FileName + ".1.gz"} {
		if _, err := os.Stat(filepath.Join(dir, kept)); err != nil {
			t.Errorf("%s removed", kept)
		}
	}
	long := strings.Repeat("x", 300)
	l.Event(Info, "BIG", F("v", long)) // larger than MaxBytes, empty file: no rotation
	l.Event(Info, "SECOND")
	l.Event(Info, "THIRD")
	l.Event(Info, "FOURTH")
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	read := func(name string) string {
		b, _ := os.ReadFile(filepath.Join(dir, name))
		return string(b)
	}
	if !strings.Contains(read(FileName+".2"), "SECOND") || !strings.Contains(read(FileName+".1"), "THIRD") || !strings.Contains(read(FileName), "FOURTH") {
		t.Fatalf("rotation order wrong: .2=%q .1=%q base=%q", read(FileName+".2"), read(FileName+".1"), read(FileName))
	}
	if strings.Contains(read(FileName+".2"), "BIG") {
		t.Error("more than BackupCount files kept")
	}
	if _, err := os.Stat(filepath.Join(dir, FileName+".3")); !errors.Is(err, os.ErrNotExist) {
		t.Error("third backup created")
	}
}

func TestSetBackupCount(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	l, err := Open(dir, Options{BackupCount: 5})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	_ = os.WriteFile(filepath.Join(dir, FileName+".4"), nil, 0o600)
	if err := l.SetBackupCount(3); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, FileName+".4")); !errors.Is(err, os.ErrNotExist) {
		t.Error("not pruned")
	}
	for _, n := range []int{0, 91} {
		if fault.CodeOf(l.SetBackupCount(n)) != fault.InvalidValue {
			t.Errorf("count %d accepted", n)
		}
	}
	if _, err := Open(dir, Options{BackupCount: 0}); err == nil {
		t.Error("Open accepted backup count 0")
	}
}

func TestRealtimeCallLogsCodeNotText(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	l, err := Open(dir, Options{BackupCount: 1})
	if err != nil {
		t.Fatal(err)
	}
	p := principaltest.User(4)
	l.RealtimeCall(context.Background(), p, "keys.upload", nil)
	l.RealtimeCall(context.Background(), p, "keys.delete", fault.Wrap(fault.StepUpRequired, errors.New("secret detail"), ""))
	l.RealtimeCall(context.Background(), p, "keys.delete", errors.New("internal detail"))
	_ = l.Close()
	raw, _ := os.ReadFile(filepath.Join(dir, FileName))
	s := string(raw)
	for _, w := range []string{"result=ok | type=keys.upload | user=user4 | user_id=4", "result=step_up_required", "result=internal"} {
		if !strings.Contains(s, w) {
			t.Errorf("missing %q in %s", w, s)
		}
	}
	if strings.Contains(s, "detail") {
		t.Error("error text reached the audit log")
	}
}

func FuzzEventMessage(f *testing.F) {
	f.Add("EVENT", "key", "va|lue\n")
	f.Add("ü", "pass_word", "\x00")
	f.Fuzz(func(t *testing.T, event, key, value string) {
		msg := eventMessage(event, []Field{F(key, value)})
		if strings.ContainsAny(msg, "\n\r\x00") {
			t.Fatalf("line break or NUL in %q", msg)
		}
		l := &Logger{opts: Options{Now: time.Now}}
		line := l.line(Info, msg)
		if strings.Count(line, "\n") != 1 || !strings.HasSuffix(line, "\n") {
			t.Fatalf("not one line: %q", line)
		}
		var rec map[string]string
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("not JSON: %v %q", err, line)
		}
		if sensitiveKey(key) && !strings.HasSuffix(rec["message"], "=[REDACTED]") {
			t.Fatalf("sensitive value logged: %q", rec["message"])
		}
	})
}

func TestSecurityPairs(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	l, err := Open(dir, Options{BackupCount: 1})
	if err != nil {
		t.Fatal(err)
	}
	l.Security("BROWSER_LOGINS_REVOKED", "user", "a", "count", 2)
	l.SecurityWarning("X", "odd")
	_ = l.Close()
	raw, _ := os.ReadFile(filepath.Join(dir, FileName))
	if !strings.Contains(string(raw), `"INFO", "logger": "security_audit", "message": "BROWSER_LOGINS_REVOKED | count=2 | user=a"`) ||
		!strings.Contains(string(raw), `"WARNING", "logger": "security_audit", "message": "X"`) {
		t.Fatalf("%s", raw)
	}
}
