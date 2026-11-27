package automation

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"io"
	"os"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/pyjson"
)

// The oracle is recorded from the Python release by testdata/oracle.py.
type oracle struct {
	Runbooks []struct {
		Input  string         `json:"input"`
		OK     jsontext.Value `json:"ok"`
		Digest *string        `json:"digest"`
		Error  string         `json:"error"`
	} `json:"runbooks"`
	Plain []struct {
		Input string `json:"input"`
		OK    string `json:"ok"`
	} `json:"plain"`
	Redact []struct {
		Input       string   `json:"input"`
		Secrets     []string `json:"secrets"`
		Interrupted bool     `json:"interrupted"`
		OK          string   `json:"ok"`
	} `json:"redact"`
	Steps []struct {
		Stdout       string   `json:"stdout"`
		StdoutRepeat int      `json:"stdout_repeat"`
		Stderr       string   `json:"stderr"`
		StderrRepeat int      `json:"stderr_repeat"`
		Status       int      `json:"status"`
		Secrets      []string `json:"secrets"`
		Budget       int      `json:"budget"`
		OK           struct {
			Status    string  `json:"status"`
			Reason    *string `json:"reason"`
			ExitCode  *int64  `json:"exit_code"`
			Stdout    string  `json:"stdout"`
			Stderr    string  `json:"stderr"`
			Truncated bool    `json:"output_truncated"`
		} `json:"ok"`
	} `json:"steps"`
	Runs []struct {
		Stored string `json:"stored"`
		JSON   struct {
			Body        string `json:"body"`
			ContentType string `json:"content_type"`
		} `json:"json"`
		CSV struct {
			Body        string `json:"body"`
			ContentType string `json:"content_type"`
		} `json:"csv"`
	} `json:"runs"`
}

func readOracle(t *testing.T) oracle {
	t.Helper()
	raw, err := os.ReadFile("testdata/oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var o oracle
	if err := json.Unmarshal(raw, &o); err != nil {
		t.Fatal(err)
	}
	return o
}

func TestNormalizeRunbookMatchesPython(t *testing.T) {
	t.Parallel()
	for _, c := range readOracle(t).Runbooks {
		v, _, err := pyjson.Load([]byte(c.Input))
		if err != nil {
			t.Fatal(err)
		}
		b, err := NormalizeRunbook(v)
		if c.Error != "" {
			if Code(err) != c.Error {
				t.Errorf("%s: error %v, want %s", c.Input, err, c.Error)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", c.Input, err)
			continue
		}
		want, _, _ := pyjson.Load(c.OK)
		if idV, _ := pyjson.Get(want, "id"); idV.Kind() == 'n' {
			if len(b.ID) != 36 {
				t.Errorf("%s: new id %q", c.Input, b.ID)
			}
			b.ID = ""
			m, _ := pyjson.Members(want)
			want = pyjson.Object(pyjson.Set(m, "id", pyjson.String("")))
		}
		if pyDump(b.Value(), dumpOptions{}) != pyDump(want, dumpOptions{}) {
			t.Errorf("%s:\n got %s\nwant %s", c.Input, b.Value(), want)
		}
		if c.Digest != nil && b.Digest() != *c.Digest {
			t.Errorf("%s: digest %s, want %s", c.Input, b.Digest(), *c.Digest)
		}
	}
}

func TestPlainOutputMatchesPython(t *testing.T) {
	t.Parallel()
	for _, c := range readOracle(t).Plain {
		if got := plainOutput(c.Input); got != c.OK {
			t.Errorf("plainOutput(%q) = %q, want %q", c.Input, got, c.OK)
		}
	}
}

func TestRedactOutputMatchesPython(t *testing.T) {
	t.Parallel()
	for _, c := range readOracle(t).Redact {
		if got := redactOutput(c.Input, c.Secrets, c.Interrupted); got != c.OK {
			t.Errorf("redactOutput(%q, %q, %v) = %q, want %q", c.Input, c.Secrets, c.Interrupted, got, c.OK)
		}
	}
}

// finishedExec is a command that already ended: its output, then its
// exit status.
type finishedExec struct {
	stdout, stderr []byte
	status         int
}

func (f finishedExec) Exec(_ context.Context, _ string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	if stdin != nil {
		_, _ = io.Copy(io.Discard, stdin)
	}
	_, _ = stdout.Write(f.stdout)
	_, _ = stderr.Write(f.stderr)
	return f.status, nil
}

func TestStepResultMatchesPython(t *testing.T) {
	t.Parallel()
	for i, c := range readOracle(t).Steps {
		out, _ := base64.StdEncoding.DecodeString(c.Stdout)
		errOut, _ := base64.StdEncoding.DecodeString(c.Stderr)
		exec := finishedExec{bytes.Repeat(out, c.StdoutRepeat), bytes.Repeat(errOut, c.StderrRepeat), c.Status}
		got := runStep(t.Context(), exec, Step{Name: "s", Command: "c", Timeout: 30}, func() bool { return false },
			c.Secrets, c.Budget, time.Now)
		w := c.OK
		if got.Status != w.Status || deref(got.Reason) != deref(w.Reason) || got.Stdout != w.Stdout ||
			got.Stderr != w.Stderr || got.Truncated != w.Truncated || !sameExit(got.ExitCode, w.ExitCode) {
			t.Errorf("case %d: got %+v\nwant %+v", i, got, w)
		}
	}
}

func deref(s *string) string {
	if s == nil {
		return "<nil>"
	}
	return *s
}

func sameExit(a, b *int64) bool { return (a == nil) == (b == nil) && (a == nil || *a == *b) }

func TestExportMatchesPython(t *testing.T) {
	t.Parallel()
	for i, c := range readOracle(t).Runs {
		v, _, err := pyjson.Load([]byte(c.Stored))
		if err != nil {
			t.Fatal(err)
		}
		r, err := ParseRun(v)
		if err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
		wantJSON, _ := base64.StdEncoding.DecodeString(c.JSON.Body)
		if got := ExportJSON(r); !bytes.Equal(got, wantJSON) {
			t.Errorf("case %d json:\n got %s\nwant %s", i, got, wantJSON)
		}
		wantCSV, _ := base64.StdEncoding.DecodeString(c.CSV.Body)
		if got := ExportCSV(r); !bytes.Equal(got, wantCSV) {
			t.Errorf("case %d csv:\n got %q\nwant %q", i, got, wantCSV)
		}
		// A stored record survives the store unchanged.
		again, err := ParseRun(r.Value())
		if err != nil || !bytes.Equal(ExportJSON(again), wantJSON) {
			t.Errorf("case %d: round trip changes the record: %v", i, err)
		}
	}
}
