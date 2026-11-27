package hosts

import (
	"context"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/realtime/protocol"
	"github.com/bifrost0x/webssh/internal/ssh/client"
	"github.com/bifrost0x/webssh/internal/store"
	"github.com/bifrost0x/webssh/internal/store/storetest"
)

// fakeDetectConn answers the probes by their script on stdin.
type fakeDetectConn struct {
	version  string
	identity func(stdout io.Writer) int // exit status; blocks for a stall
	reboot   string
	done     chan struct{}

	mu    sync.Mutex
	execs []string
}

func (f *fakeDetectConn) ServerVersion() string { return f.version }
func (f *fakeDetectConn) Done() <-chan struct{} { return f.done }

func (f *fakeDetectConn) Exec(ctx context.Context, line string, stdin io.Reader, stdout, _ io.Writer) (int, error) {
	script, _ := io.ReadAll(stdin)
	if line != `sh -c 'eval "$(cat)"'` {
		return 127, nil
	}
	f.mu.Lock()
	kind := "other"
	switch string(script) {
	case IdentityScript:
		kind = "identity"
	case RebootHintScript:
		kind = "reboot"
	}
	f.execs = append(f.execs, kind)
	f.mu.Unlock()
	switch kind {
	case "identity":
		status := 0
		finished := make(chan struct{})
		go func() { status = f.identity(stdout); close(finished) }()
		select {
		case <-finished:
			return status, nil
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	case "reboot":
		_, _ = io.WriteString(stdout, f.reboot)
		return 0, nil
	}
	return 1, nil
}

func (f *fakeDetectConn) ran() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.execs...)
}

func answer(text string, status int) func(io.Writer) int {
	return func(w io.Writer) int { _, _ = io.WriteString(w, text); return status }
}

type sent struct {
	typ     string
	payload any
}

type detectFixture struct {
	s      *Service
	d      *Detector
	mu     sync.Mutex
	events []sent
}

func newDetectFixture(t *testing.T, profiles ...string) *detectFixture {
	t.Helper()
	db := storetest.Open(t, Schema())
	var values []jsontext.Value
	for _, p := range profiles {
		values = append(values, jsontext.Value(p))
	}
	if err := db.Write(t.Context(), func(tx *store.Tx) error {
		_, err := Import(t.Context(), tx, oracleUser, Legacy{Profiles: values}, DefaultLimits)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	f := &detectFixture{s: &Service{DB: db, Limits: DefaultLimits}}
	f.d = &Detector{Hosts: f.s, Describe: func(line []byte) (string, bool) {
		switch {
		case strings.Contains(string(line), "Windows"):
			return "windows", true
		case strings.Contains(string(line), "Debian"):
			return "debian", true
		}
		return "", strings.HasPrefix(string(line), "SSH-")
	}, Notify: func(_ int64, typ string, payload any) {
		f.mu.Lock()
		f.events = append(f.events, sent{typ, payload})
		f.mu.Unlock()
	}}
	return f
}

func (f *detectFixture) run(t *testing.T, id string, conn *fakeDetectConn) {
	t.Helper()
	if conn.done == nil {
		conn.done = make(chan struct{})
	}
	target := client.Target{Owner: oracleUser, Hop: client.Hop{Host: id + ".lan", Port: 22, User: "ops"},
		Display: client.Display{ProfileID: id}}
	f.d.Connected(t.Context(), target, conn)
	f.d.wg.Wait()
}

func (f *detectFixture) profile(t *testing.T, id string) map[string]any {
	t.Helper()
	profiles, err := f.s.Profiles(t.Context(), oracleUser)
	if err != nil {
		t.Fatal(err)
	}
	return objects(t, profiles)[id]
}

func savedHost(id string, extra string) string {
	return `{"name":"` + id + `","host":"` + id + `.lan","port":22,"username":"ops","auth_type":"password","key_id":null,` +
		`"startup_mode":"none","id":"` + id + `","sort_order":1` + extra + `}`
}

const debianAnswer = "ID=debian\nVERSION_ID=\"12\"\nkernel=Linux\nvirt=kvm\nunit=nginx\nservice=docker\nengine=docker:ok\n"

func TestDetectorStoresTheIdentityOncePerWeek(t *testing.T) {
	f := newDetectFixture(t, savedHost("plain", ""))
	conn := &fakeDetectConn{version: "SSH-2.0-OpenSSH_9.2p1 Debian-2", identity: answer(debianAnswer, 0)}
	f.run(t, "plain", conn)
	p := f.profile(t, "plain")
	if p["detected_platform"] != "debian" || p["detection_state"] != "detected" || p["detected_virt"] != "vm" ||
		p["detected_container_access"] != "ok" || p["greeting_platform"] != "debian" || p["authenticated_greeting"] != "debian" {
		t.Fatalf("stored facts: %v", p)
	}
	if len(f.events) != 1 || f.events[0].typ != protocol.TypeDiscoveryPlatform {
		t.Fatalf("events %+v", f.events)
	}
	ev := f.events[0].payload.(protocol.DiscoveryPlatform)
	raw, _ := json.Marshal(ev)
	if ev.Platform != "debian" || strings.Join(ev.Services, ",") != "docker,nginx" || ev.Identity == nil ||
		!strings.Contains(string(raw), `"profile_id":"plain"`) {
		t.Fatalf("payload %s", raw)
	}
	// A second connection within the week runs no probe.
	again := &fakeDetectConn{version: conn.version, identity: answer(debianAnswer, 0)}
	f.run(t, "plain", again)
	if got := again.ran(); len(got) != 0 {
		t.Fatalf("probe ran again: %v", got)
	}
}

func TestDetectorAnswersWithoutFacts(t *testing.T) {
	stuck := make(chan struct{})
	t.Cleanup(func() { close(stuck) })
	cases := []struct {
		name     string
		identity func(io.Writer) int
		state    any
		checked  func(at float64, now time.Time) bool
	}{
		{"forced command", answer("Welcome to the backup menu\n", 0), "unavailable",
			func(at float64, now time.Time) bool { return now.Sub(pyTime(at)) < time.Minute }},
		{"non-zero exit", answer(debianAnswer, 1), "unavailable",
			func(at float64, now time.Time) bool { return now.Sub(pyTime(at)) < time.Minute }},
		{"stalled after its own lines", func(w io.Writer) int {
			_, _ = io.WriteString(w, "ID=debian\nkernel=Linux\n")
			<-stuck
			return 0
		}, nil, func(at float64, now time.Time) bool {
			// Recorded as six days old: due again after one day.
			return now.Sub(pyTime(at)) > (IdentityRefresh-SilentRetry)-time.Minute
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newDetectFixture(t, savedHost("h", ""))
			f.d.timeout = 100 * time.Millisecond
			f.run(t, "h", &fakeDetectConn{version: "SSH-2.0-OpenSSH_9.6", identity: c.identity})
			p := f.profile(t, "h")
			if p["detection_state"] != c.state || p["detected_platform"] != nil {
				t.Fatalf("stored: %v", p)
			}
			at, _ := p["platform_checked_at"].(float64)
			if !c.checked(at, time.Now()) {
				t.Fatalf("check time %v", at)
			}
		})
	}
}

func TestDetectorSkipsWhatPythonSkips(t *testing.T) {
	f := newDetectFixture(t, savedHost("manual", `,"platform_icon":"proxmox"`), savedHost("win", ""))
	manual := &fakeDetectConn{version: "SSH-2.0-OpenSSH_9.6", identity: answer(debianAnswer, 0)}
	f.run(t, "manual", manual)
	if got := manual.ran(); len(got) != 0 {
		t.Fatalf("probe ran for a manual icon: %v", got)
	}
	win := &fakeDetectConn{version: "SSH-2.0-OpenSSH_for_Windows_9.5", identity: answer(debianAnswer, 0)}
	f.run(t, "win", win)
	if got := win.ran(); len(got) != 0 {
		t.Fatalf("probe ran on a host without a POSIX shell: %v", got)
	}
	if p := f.profile(t, "win"); p["greeting_platform"] != "windows" {
		t.Fatalf("windows greeting not stored: %v", p)
	}
	quick := &fakeDetectConn{version: "SSH-2.0-OpenSSH_9.6", identity: answer(debianAnswer, 0), done: make(chan struct{})}
	f.d.Connected(t.Context(), client.Target{Owner: oracleUser, Hop: client.Hop{Host: "x", Port: 22, User: "u"}}, quick)
	f.d.wg.Wait()
	if got := quick.ran(); len(got) != 0 {
		t.Fatalf("quick connection probed: %v", got)
	}
	// An edited endpoint (another user name) is not the saved host.
	other := &fakeDetectConn{version: "SSH-2.0-OpenSSH_9.6", identity: answer(debianAnswer, 0), done: make(chan struct{})}
	f.d.Connected(t.Context(), client.Target{Owner: oracleUser, Hop: client.Hop{Host: "manual.lan", Port: 22, User: "root"},
		Display: client.Display{ProfileID: "manual"}}, other)
	f.d.wg.Wait()
	if got := other.ran(); len(got) != 0 {
		t.Fatalf("other login probed: %v", got)
	}
}

func TestDetectorRechecksTheRestartHint(t *testing.T) {
	hint := func(at float64) string {
		return `,"platform_icon":"debian","detected_maintenance":{"reboot_required":true,"updates":2,"security_updates":0,"checked_at":` +
			jsonFloat(at) + `}`
	}
	now := float64(time.Now().UnixMicro())/1e6 - 3600
	for _, c := range []struct {
		answer string
		want   map[string]any
		event  bool
	}{
		{"reboot=no\n", map[string]any{"reboot_required": false}, true},
		{"reboot=yes\n", map[string]any{"reboot_required": true}, false},
		{"Last login: yesterday\n", map[string]any{"reboot_required": true, "recheck_stopped": true}, false},
	} {
		f := newDetectFixture(t, savedHost("h", hint(now)))
		conn := &fakeDetectConn{version: "SSH-2.0-OpenSSH_9.6", reboot: c.answer}
		f.run(t, "h", conn)
		m := f.profile(t, "h")["detected_maintenance"].(map[string]any)
		for k, v := range c.want {
			if m[k] != v {
				t.Errorf("%q: %s = %v, want %v", c.answer, k, m[k], v)
			}
		}
		if got := conn.ran(); len(got) != 1 || got[0] != "reboot" {
			t.Errorf("%q: commands %v", c.answer, got)
		}
		if (len(f.events) == 1) != c.event {
			t.Errorf("%q: events %+v", c.answer, f.events)
		}
	}
}

func jsonFloat(f float64) string { b, _ := json.Marshal(f); return string(b) }

func TestDetectorIsBounded(t *testing.T) {
	f := newDetectFixture(t, savedHost("a", ""), savedHost("b", ""))
	f.d.MaxActive = 1
	release := make(chan struct{})
	slow := &fakeDetectConn{version: "SSH-2.0-OpenSSH_9.6", done: make(chan struct{}),
		identity: func(w io.Writer) int { <-release; _, _ = io.WriteString(w, debianAnswer); return 0 }}
	f.d.Connected(t.Context(), client.Target{Owner: oracleUser, Hop: client.Hop{Host: "a.lan", Port: 22, User: "ops"},
		Display: client.Display{ProfileID: "a"}}, slow)
	for len(slow.ran()) == 0 {
		time.Sleep(time.Millisecond)
	}
	second := &fakeDetectConn{version: "SSH-2.0-OpenSSH_9.6", identity: answer(debianAnswer, 0), done: make(chan struct{})}
	f.d.Connected(t.Context(), client.Target{Owner: oracleUser, Hop: client.Hop{Host: "b.lan", Port: 22, User: "ops"},
		Display: client.Display{ProfileID: "b"}}, second)
	close(release)
	if err := f.d.Shutdown(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := second.ran(); len(got) != 0 {
		t.Fatalf("detection over the bound ran: %v", got)
	}
	// After Shutdown nothing starts.
	f.d.Connected(t.Context(), client.Target{Owner: oracleUser, Display: client.Display{ProfileID: "b"}}, second)
	if got := second.ran(); len(got) != 0 {
		t.Fatalf("detection after shutdown ran: %v", got)
	}
}

func TestDetectorStopsWithTheConnection(t *testing.T) {
	stuck := make(chan struct{})
	t.Cleanup(func() { close(stuck) })
	f := newDetectFixture(t, savedHost("h", ""))
	f.d.timeout = time.Minute
	conn := &fakeDetectConn{version: "SSH-2.0-OpenSSH_9.6", done: make(chan struct{}),
		identity: func(io.Writer) int { <-stuck; return 0 }}
	f.d.Connected(t.Context(), client.Target{Owner: oracleUser, Hop: client.Hop{Host: "h.lan", Port: 22, User: "ops"},
		Display: client.Display{ProfileID: "h"}}, conn)
	for len(conn.ran()) == 0 {
		time.Sleep(time.Millisecond)
	}
	close(conn.done)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if err := f.d.Shutdown(ctx); err != nil {
		t.Fatalf("detection did not end with its connection: %v", err)
	}
	if p := f.profile(t, "h"); p["detection_state"] != nil || p["platform_checked_at"] == nil {
		t.Fatalf("a probe cut short stored facts: %v", p)
	}
}
