package terminal

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"io"
	"log/slog"
	"maps"
	"sync"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal/principaltest"
	"github.com/bifrost0x/webssh/internal/quota"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
	"github.com/bifrost0x/webssh/internal/realtime/protocol/protocoltest"
	"github.com/bifrost0x/webssh/internal/ssh/client"
)

type (
	peerT         = protocoltest.Peer
	protocolEvent = protocoltest.Event
)

// fakeShell produces output on demand and records input and resizes.
type fakeShell struct {
	out    chan []byte
	closed chan struct{}
	once   sync.Once
	mu     sync.Mutex
	input  bytes.Buffer
	sizes  [][2]int
	block  chan struct{} // when set, Write waits for it
}

func newFakeShell() *fakeShell {
	return &fakeShell{out: make(chan []byte), closed: make(chan struct{})}
}

func (f *fakeShell) Read(p []byte) (int, error) {
	select {
	case b := <-f.out:
		return copy(p, b), nil
	case <-f.closed:
		return 0, io.EOF
	}
}

func (f *fakeShell) Write(p []byte) (int, error) {
	if f.block != nil {
		select {
		case <-f.block:
		case <-f.closed:
			return 0, io.ErrClosedPipe
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.input.Write(p)
}

func (f *fakeShell) Resize(rows, cols int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sizes = append(f.sizes, [2]int{rows, cols})
	return nil
}

func (f *fakeShell) Wait() error  { <-f.closed; return nil }
func (f *fakeShell) Close() error { f.once.Do(func() { close(f.closed) }); return nil }

func (f *fakeShell) isClosed() bool {
	select {
	case <-f.closed:
		return true
	default:
		return false
	}
}

func (f *fakeShell) typed() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.input.String()
}

// push offers one read; false if the reader did not take it in time.
func (f *fakeShell) push(t *testing.T, s string) {
	t.Helper()
	select {
	case f.out <- []byte(s):
	case <-time.After(2 * time.Second):
		t.Fatalf("shell output %q not read", s)
	}
}

// fakeShells opens fake shells; a test may run prompts through ix first
// or make the attempt fail.
type fakeShells struct {
	mu      sync.Mutex
	opened  []*fakeShell
	targets []client.Target
	before  func(ctx context.Context, ix client.Interaction) error
}

func (s *fakeShells) OpenShell(ctx context.Context, t client.Target, ix client.Interaction, _, _ int) (client.Shell, error) {
	s.mu.Lock()
	s.targets = append(s.targets, t)
	before := s.before
	s.mu.Unlock()
	if before != nil {
		if err := before(ctx, ix); err != nil {
			return nil, err
		}
	}
	sh := newFakeShell()
	s.mu.Lock()
	s.opened = append(s.opened, sh)
	s.mu.Unlock()
	return sh, nil
}

func (s *fakeShells) last(t *testing.T) *fakeShell {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.opened) == 0 {
		t.Fatal("no shell opened")
	}
	return s.opened[len(s.opened)-1]
}

type fakeProfiles map[string]client.Target

func (p fakeProfiles) Resolve(_ context.Context, owner int64, id string) (client.Target, error) {
	t, ok := p[id]
	if !ok || t.Owner != owner {
		return client.Target{}, fault.New(fault.NotFound, "")
	}
	return t, nil
}

func newManager(t *testing.T, cfg Config, shells Shells) *Manager {
	t.Helper()
	return newLimited(t, 10, 5, cfg, shells)
}

// testQuotas is the quota policy with the given session limits and the
// defaults of the other kinds.
func testQuotas(t testing.TB, global, perUser int64) Quotas {
	t.Helper()
	limits := maps.Clone(quota.DefaultLimits)
	limits[quota.SSHSession] = quota.Limit{Global: global, PerUser: perUser}
	p, err := quota.New(limits)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// newLimited is newManager with the session limits global and perUser.
func newLimited(t *testing.T, global, perUser int64, cfg Config, shells Shells) *Manager {
	t.Helper()
	m, err := New(cfg, Deps{Shells: shells, Log: slog.New(slog.DiscardHandler), Quotas: testQuotas(t, global, perUser)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := m.Shutdown(ctx); err != nil {
			t.Errorf("shutdown: %v", err)
		}
	})
	return m
}

func route(t *testing.T, m *Manager, typ string) protocol.Route {
	t.Helper()
	for _, r := range m.Routes() {
		if r.Type == typ {
			return r
		}
	}
	t.Fatalf("no route %s", typ)
	return protocol.Route{}
}

// call runs a route like the dispatcher and decodes its result into out.
func call(t *testing.T, m *Manager, peer protocol.Peer, typ string, payload, out any) *protocol.Error {
	t.Helper()
	raw, werr := protocoltest.Call(t.Context(), route(t, m, typ), peer, payload)
	if werr == nil && out != nil && raw != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			t.Fatal(err)
		}
	}
	return werr
}

func user(t *testing.T, id int64) *protocoltest.Peer {
	return protocoltest.NewPeer(t, principaltest.User(id))
}

func openReq(ch uint32, rid string) protocol.TerminalOpen {
	return protocol.TerminalOpen{Ch: ch, RequestID: rid, Rows: 24, Cols: 80,
		Target: protocol.OpenTarget{Host: "h.example", Port: 22, Username: "u", AuthType: "password", Password: "pw"}}
}

// open runs terminal.open and fails the test on an error.
func open(t *testing.T, m *Manager, peer protocol.Peer, ch uint32) protocol.TerminalOpened {
	t.Helper()
	var res protocol.TerminalOpened
	if werr := call(t, m, peer, protocol.TypeTerminalOpen, openReq(ch, "r"+string(rune('a'+ch%26))), &res); werr != nil {
		t.Fatalf("open: %+v", werr)
	}
	return res
}

// frames decodes the binary frames a peer received.
func frames(t *testing.T, p *protocoltest.Peer) []protocol.Frame {
	t.Helper()
	var out []protocol.Frame
	for _, b := range p.Frames() {
		f := protocol.Frame{Kind: protocol.Kind(b[0]), Flags: b[1]}
		f.Channel = uint32(b[2])<<24 | uint32(b[3])<<16 | uint32(b[4])<<8 | uint32(b[5])
		for _, x := range b[6:14] {
			f.Seq = f.Seq<<8 | uint64(x)
		}
		f.Data = b[14:]
		out = append(out, f)
	}
	return out
}

// output joins the data of the output frames on channel ch.
func output(t *testing.T, p *protocoltest.Peer, ch uint32) string {
	var b bytes.Buffer
	for _, f := range frames(t, p) {
		if f.Kind == protocol.KindOutput && f.Channel == ch {
			b.Write(f.Data)
		}
	}
	return b.String()
}

// eventually polls cond for up to two seconds.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func input(ch uint32, seq uint64, data string, wantAck bool) []byte {
	var flags uint8
	if wantAck {
		flags = protocol.FlagWantAck
	}
	return protocol.AppendFrame(nil, protocol.Frame{Kind: protocol.KindInput, Flags: flags, Channel: ch, Seq: seq, Data: []byte(data)})
}

func ack(ch uint32, seq uint64) []byte {
	return protocol.AppendFrame(nil, protocol.Frame{Kind: protocol.KindAck, Channel: ch, Seq: seq})
}

func decode[T any](t *testing.T, e protocoltest.Event) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(e.Payload, &v); err != nil {
		t.Fatal(err)
	}
	return v
}
