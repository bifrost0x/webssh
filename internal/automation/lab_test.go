//go:build lab

// The lab test runs workflows with the real dialer against ssh-modern of
// the shared test lab (tests/lab), signing in with a saved password:
//
//	WEBSSH_LAB_JSON=…/tests/lab/runtime/lab.json go test -tags lab -run Lab ./internal/automation
//
// It fails, not skips, when the lab is not reachable.
package automation

import (
	"context"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/netpolicy"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/principal/principaltest"
	"github.com/bifrost0x/webssh/internal/ssh/client"
	"github.com/bifrost0x/webssh/internal/ssh/hostkey"
	"github.com/bifrost0x/webssh/internal/store"
	"github.com/bifrost0x/webssh/internal/store/storetest"
)

type labFile struct {
	RuntimeDir string `json:"runtime_dir"`
	Services   map[string]struct {
		Host string `json:"host"`
		Port int    `json:"port"`
	} `json:"services"`
}

type labDialer struct{ d *client.Dialer }

func (l labDialer) Dial(ctx context.Context, t client.Target, ix client.Interaction) (Conn, error) {
	return l.d.Dial(ctx, t, ix)
}

type labTrust struct{ s *hostkey.Store }

func (l labTrust) Trusted(ctx context.Context, owner int64, host string, port int) (bool, error) {
	r, err := l.s.Effective(ctx, owner, []hostkey.Target{{Host: host, Port: port}})
	if err != nil || len(r) != 1 {
		return false, err
	}
	for _, k := range r[0].Keys {
		if k.Status == "effective" {
			return true, nil
		}
	}
	return false, nil
}

type acceptOnce struct{}

func (acceptOnce) HostKey(context.Context, client.HostKeyPrompt) (bool, error) { return true, nil }
func (acceptOnce) Banner(context.Context, client.BannerPrompt) (bool, error)   { return true, nil }

func TestLabWorkflows(t *testing.T) {
	path := os.Getenv("WEBSSH_LAB_JSON")
	if path == "" {
		path = filepath.Join("..", "..", "tests", "lab", "runtime", "lab.json")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("lab not available (set WEBSSH_LAB_JSON): %v", err)
	}
	var l labFile
	if err := json.Unmarshal(raw, &l); err != nil {
		t.Fatal(err)
	}
	pwRaw, err := os.ReadFile(filepath.Join(l.RuntimeDir, "secrets/ssh-pwuser"))
	if err != nil {
		t.Fatal(err)
	}
	pw := strings.TrimSpace(string(pwRaw))
	s := l.Services["ssh-modern"]
	log := slog.New(slog.DiscardHandler)
	policy, err := netpolicy.New(netpolicy.Config{Logger: log})
	if err != nil {
		t.Fatal(err)
	}
	db := storetest.Open(t, hostkey.Schema(), Schema())
	keys := hostkey.New(db, log)
	d := &client.Dialer{Net: policy, HostKeys: keys}

	// Without a trusted host key the review fails and names the host.
	w := newWorld()
	w.profiles = []string{`{"id":"lab","name":"Lab modern","host":"` + s.Host + `","port":` + strconv.Itoa(s.Port) +
		`,"username":"pwuser","auth_type":"password","group":"Lab"}`}
	w.jumps = nil
	w.passwords = map[string]string{"lab": pw}
	w.bindings = map[string]string{"lab": "g1"}
	steps := &principaltest.StepUp{}
	svc, err := New(Options{DB: db, Records: w, Passwords: w, Keys: w, HostTrust: labTrust{keys}, Resolver: w,
		Dialer: labDialer{d}, Switches: w, Quotas: w, StepUp: steps, Logger: log})
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	book := func(body string) Runbook {
		v := jsontext.Value(body)
		b, err := svc.SaveRunbook(ctx, owner, v)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	first := book(`{"name":"Probe","steps":[{"name":"id","command":"id -un"}]}`)
	if _, err := svc.Freeze(ctx, owner, first.ID, []string{"lab"}, nil); Code(err) != "host_key_required" {
		t.Fatalf("unknown host key: %v", err)
	}
	// The user verifies the key in an interactive connection first.
	conn, err := d.Dial(ctx, client.Target{Owner: owner, Hop: client.Hop{Host: s.Host, Port: s.Port, User: "pwuser",
		Auth: client.Auth{Password: pw}}}, acceptOnce{})
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()

	run := func(b Runbook) Run {
		t.Helper()
		f, err := svc.Freeze(ctx, owner, b.ID, []string{"lab"}, nil)
		if err != nil {
			t.Fatal(err)
		}
		r, err := svc.dispatch(ctx, job{userID: owner, sessionID: "s", frozen: f})
		if err != nil {
			t.Fatal(err)
		}
		deadline := time.Now().Add(60 * time.Second)
		for time.Now().Before(deadline) {
			got, err := svc.Run(ctx, owner, r.ID)
			if err == nil && terminal(got.Status) {
				waitIdle(t, svc)
				return got
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatalf("run %s did not finish", r.ID)
		return Run{}
	}

	ok := run(book(`{"name":"Lab","steps":[
		{"name":"user","command":"id -un"},
		{"name":"leak","command":"echo ` + pw + `"},
		{"name":"big","command":"head -c 300000 /dev/zero | tr '\\\\0' x"},
		{"name":"multi","command":"printf 'a\\033[31mred\\033[0m\\n'\necho \"$PWD\" >&2\nexit 3"},
		{"name":"after","command":"true"}]}`))
	st := ok.Targets[0].Steps
	if ok.Status != StatusFailed || st[0].Name != "user" || st[0].Status != StatusSucceeded || st[0].Stdout != "pwuser\n" {
		t.Fatalf("first step: %+v", ok)
	}
	if strings.Contains(st[1].Stdout, pw) || st[1].Stdout != "[redacted]\n" {
		t.Errorf("password echoed: %q", st[1].Stdout)
	}
	if !st[2].Truncated || len(st[2].Stdout)+len(st[2].Stderr) > StepOutputBytes || st[2].Status != StatusSucceeded {
		t.Errorf("large output: status %s truncated %v len %d", st[2].Status, st[2].Truncated, len(st[2].Stdout))
	}
	if st[3].Status != StatusFailed || *st[3].ExitCode != 3 || st[3].Stdout != "ared\n" || !strings.HasPrefix(st[3].Stderr, "/") {
		t.Errorf("multi-line step: %+v", st[3])
	}
	if st[4].Status != StatusSkipped {
		t.Errorf("step after a failure: %+v", st[4])
	}
	sudo := run(book(`{"name":"Sudo","steps":[{"name":"sudo","command":"true","sudo":true}]}`)).Targets[0].Steps[0]
	if sudo.Status != StatusFailed || sudo.ExitCode == nil || *sudo.ExitCode == 0 {
		t.Errorf("sudo without a password prompt: %+v", sudo)
	}
	slow := run(book(`{"name":"Slow","steps":[{"name":"slow","command":"echo begin; sleep 5","timeout":1}]}`))
	if s := slow.Targets[0].Steps[0]; slow.Status != StatusUnknown || s.Status != StatusUnknown || *s.Reason != "timeout" || s.Stdout != "begin\n" {
		t.Errorf("timeout: %+v", slow)
	}
	// The step is the exec request, as in Python: the login shell of the
	// account reads it unchanged, so the shell's own syntax works (here
	// [[ ]], $'…' and ${var/…/…}, which busybox ash shares with Bash) and
	// the shell's command line is the step itself, not a wrapper.
	shellSyntax := `[[ -n "$HOME" ]] && x=$'\x41' && s=abc && echo "$x ${s/b/B}"`
	ownLine := `line=$(tr '\0' '|' </proc/$$/cmdline); echo "$line"`
	shellBook, err := json.Marshal(map[string]any{"name": "Shell", "steps": []map[string]any{
		{"name": "syntax", "command": shellSyntax}, {"name": "line", "command": ownLine}}})
	if err != nil {
		t.Fatal(err)
	}
	shell := run(book(string(shellBook))).Targets[0].Steps
	if shell[0].Status != StatusSucceeded || shell[0].Stdout != "A aBc\n" {
		t.Errorf("shell syntax step: %+v", shell[0])
	}
	if shell[1].Status != StatusSucceeded || !strings.HasSuffix(shell[1].Stdout, "|-c|"+ownLine+"|\n") {
		t.Errorf("the login shell did not get the step as its command: %+v", shell[1])
	}
	labScheduledRun(t, svc, first)
	_ = db.Read(ctx, func(tx *store.Tx) error { return nil })
}

// labScheduledRun runs a runbook the way a due schedule does, through
// the run side of the schedules (Workflows): review, the check of the
// approval, then the start without a session against ssh-modern.
func labScheduledRun(t *testing.T, svc *Service, b Runbook) {
	t.Helper()
	ctx := t.Context()
	w := svc.Workflows()
	snap, err := w.Review(ctx, principal.Principal{UserID: owner, SessionID: "s"},
		jsontext.Value(`{"runbook_id":"`+b.ID+`","profile_ids":["lab"]}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Current(ctx, owner, snap); err != nil {
		t.Fatalf("a fresh approval does not hold: %v", err)
	}
	checks := 0
	finished := make(chan string, 1)
	err = w.StartScheduled(ctx, ScheduledRun{UserID: owner, ScheduleID: "lab-schedule", ClaimID: "lab-claim-1", Snapshot: snap,
		Check:  func(context.Context) error { checks++; return nil },
		Finish: func(_ context.Context, status string) { finished <- status }})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case status := <-finished:
		if status != StatusSucceeded || checks == 0 {
			t.Fatalf("scheduled run: %s after %d checks", status, checks)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("the scheduled run did not finish")
	}
	waitIdle(t, svc)
	runs, err := svc.History(ctx, owner)
	if err != nil || len(runs) == 0 || runs[0].ScheduleID == nil || *runs[0].ScheduleID != "lab-schedule" ||
		runs[0].Targets[0].Steps[0].Stdout != "pwuser\n" {
		t.Fatalf("history of the scheduled run: %+v, %v", runs, err)
	}
}

func waitIdle(t *testing.T, s *Service) {
	t.Helper()
	for range 500 {
		s.mu.Lock()
		n := len(s.active)
		s.mu.Unlock()
		if n == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("run still active")
}
