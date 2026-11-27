package automation

import (
	"context"
	"encoding/json/jsontext"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal/principaltest"
	"github.com/bifrost0x/webssh/internal/ssh/client"
	"github.com/bifrost0x/webssh/internal/store/storetest"
	"github.com/bifrost0x/webssh/internal/vault"
)

const owner = int64(7)

// world is the saved hosts, keys, trust and passwords of the test user.
type world struct {
	mu        sync.Mutex
	profiles  []string
	jumps     []string
	trusted   map[string]bool
	keys      map[string][]byte
	passwords map[string]string // resource id -> secret
	bindings  map[string]string // resource id -> token
	enabled   bool
	dials     []client.Target
	scripts   []string
	quota     int
}

func newWorld() *world {
	return &world{
		profiles: []string{
			`{"id":"p1","name":"Web","host":"web.test","port":22,"username":"ops","auth_type":"key","key_id":"k1","group":"Lab"}`,
			`{"id":"p2","name":"Db","host":"db.test","port":2222,"username":"dba","auth_type":"password","jump_host_id":"j1","group":"Lab"}`,
			`{"id":"p3","name":"Proxied","host":"x.test","port":22,"username":"u","auth_type":"key","key_id":"k1","socks_proxy_id":"s1"}`,
		},
		jumps:     []string{`{"id":"j1","name":"Bastion","host":"bastion.test","port":22,"username":"jump","auth_type":"key","key_id":"k1"}`},
		trusted:   map[string]bool{"web.test:22": true, "db.test:2222": true, "bastion.test:22": true, "x.test:22": true},
		keys:      map[string][]byte{"k1": []byte("public-key-1")},
		passwords: map[string]string{"p2": "s3cret-pw"},
		bindings:  map[string]string{"p2": "gen-1"},
		enabled:   true,
	}
}

func (w *world) Records(context.Context, int64) (vault.Records, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	var r vault.Records
	for _, p := range w.profiles {
		r.Profiles = append(r.Profiles, jsontext.Value(p))
	}
	for _, j := range w.jumps {
		r.JumpHosts = append(r.JumpHosts, jsontext.Value(j))
	}
	return r, nil
}

func (w *world) Password(_ context.Context, userID int64, id string, _ vault.Target) ([]byte, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	pw, ok := w.passwords[id]
	if !ok || userID != owner {
		return nil, fault.New(fault.CredentialMissing, "")
	}
	return []byte(pw), nil
}

func (w *world) Binding(_ context.Context, _ int64, id string, _ vault.Target) (vault.Status, string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if b, ok := w.bindings[id]; ok {
		return vault.StatusReady, b, nil
	}
	return vault.StatusMissing, "", nil
}

func (w *world) PublicKey(_ context.Context, _ int64, id string) ([]byte, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if k, ok := w.keys[id]; ok {
		return k, nil
	}
	return nil, errors.New("no key")
}

func (w *world) Trusted(_ context.Context, _ int64, host string, port int) (bool, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.trusted[host+":"+itoa(int64(port))], nil
}

// Resolve builds the target from the records as internal/hosts does.
func (w *world) Resolve(ctx context.Context, userID int64, id string) (client.Target, error) {
	r, _ := w.Records(ctx, userID)
	inv := newInventory(r)
	h, ok := inv.byID(id)
	if !ok {
		return client.Target{}, fault.New(fault.NotFound, "")
	}
	t := client.Target{Owner: userID, Hop: client.Hop{Host: h.Host, Port: int(h.Port), User: h.Username}}
	if route := inv.route(h); route != nil {
		t.Jumps = []client.Hop{{Host: route.Host, Port: int(route.Port), User: route.Username}}
	}
	return t, nil
}

func (w *world) Dial(_ context.Context, t client.Target, ix client.Interaction) (Conn, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, ok := ix.(Unattended); !ok {
		return nil, errors.New("attended dial")
	}
	if t.Hop.Host == "down.test" {
		return nil, fault.New(fault.AuthFailed, "")
	}
	w.dials = append(w.dials, t)
	return &fakeConn{w: w}, nil
}

func (w *world) AutomationEnabled(context.Context) (bool, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.enabled, nil
}

func (w *world) CredentialsEnabled(context.Context) (bool, error) { return true, nil }

func (w *world) Reserve(_ context.Context, _ string, _, _ int64) (func(), error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.quota++
	return func() {
		w.mu.Lock()
		w.quota--
		w.mu.Unlock()
	}, nil
}

func (w *world) set(fn func(w *world)) {
	w.mu.Lock()
	defer w.mu.Unlock()
	fn(w)
}

// fakeConn runs the scripts: "fail" exits 2, "wait" blocks until the
// context ends, "leak" prints the password, anything else prints "ok".
type fakeConn struct{ w *world }

func (c *fakeConn) Exec(ctx context.Context, line string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	if !strings.Contains(line, `eval "$(cat)"`) {
		return -1, errors.New("the script is not on stdin")
	}
	raw, _ := io.ReadAll(stdin)
	script := string(raw)
	c.w.mu.Lock()
	c.w.scripts = append(c.w.scripts, line+"|"+script)
	c.w.mu.Unlock()
	switch script {
	case "fail":
		_, _ = stderr.Write([]byte("boom\n"))
		return 2, nil
	case "wait":
		_, _ = stdout.Write([]byte("started\n"))
		<-ctx.Done()
		return -1, ctx.Err()
	case "leak":
		_, _ = stdout.Write([]byte("pw is s3cret-pw\n"))
		return 0, nil
	}
	_, _ = stdout.Write([]byte("ok " + script + "\n"))
	return 0, nil
}

func (c *fakeConn) Close() error { return nil }

func newService(t *testing.T, w *world) (*Service, *principaltest.StepUp) {
	t.Helper()
	steps := &principaltest.StepUp{}
	s, err := New(Options{DB: storetest.Open(t, Schema()), Records: w, Passwords: w, Keys: w, HostTrust: w,
		Resolver: w, Dialer: w, Switches: w, Quotas: w, StepUp: steps})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.Shutdown(ctx)
	})
	return s, steps
}
