package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"io"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/bifrost0x/webssh/internal/netpolicy"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/principal/principaltest"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
	"github.com/bifrost0x/webssh/internal/realtime/protocol/protocoltest"
	"github.com/bifrost0x/webssh/internal/ssh/client"
)

// sshHost is an in-process SSH server for the terminal path. Every login
// passes, a shell or "tmux new-session" echoes, any other command exits
// 0, and a direct-tcpip channel reaches the server's own listener whatever
// the client asked for. One server so stands in for a jump host and for
// the tailnet node behind it.
type sshHost struct {
	addr *net.TCPAddr
	key  ssh.PublicKey

	mu       sync.Mutex
	open     map[net.Conn]bool // accepted TCP connections
	conns    int               // open SSH connections
	commands []string
	forwards []string
}

func startSSHHost(t *testing.T) *sshHost {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) { return nil, nil }}
	cfg.AddHostKey(signer)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h := &sshHost{addr: l.Addr().(*net.TCPAddr), key: signer.PublicKey(), open: map[net.Conn]bool{}}
	var wg sync.WaitGroup
	// The terminal may still hold sessions when the test ends.
	t.Cleanup(func() {
		_ = l.Close()
		h.mu.Lock()
		for c := range h.open {
			_ = c.Close()
		}
		h.mu.Unlock()
		wg.Wait()
	})
	wg.Go(func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			h.mu.Lock()
			h.open[conn] = true
			h.mu.Unlock()
			wg.Go(func() {
				h.serve(conn, cfg)
				h.mu.Lock()
				delete(h.open, conn)
				h.mu.Unlock()
			})
		}
	})
	return h
}

func (h *sshHost) serve(conn net.Conn, cfg *ssh.ServerConfig) {
	defer func() { _ = conn.Close() }()
	sc, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		return
	}
	h.count(1)
	defer h.count(-1)
	defer func() { _ = sc.Close() }()
	go ssh.DiscardRequests(reqs)
	var wg sync.WaitGroup
	defer wg.Wait()
	for nc := range chans {
		switch nc.ChannelType() {
		case "direct-tcpip":
			wg.Go(func() { h.forward(nc) })
		case "session":
			wg.Go(func() { h.session(nc) })
		default:
			_ = nc.Reject(ssh.UnknownChannelType, "")
		}
	}
}

func (h *sshHost) count(d int) {
	h.mu.Lock()
	h.conns += d
	h.mu.Unlock()
}

func (h *sshHost) forward(nc ssh.NewChannel) {
	var req struct {
		Host       string
		Port       uint32
		OriginHost string
		OriginPort uint32
	}
	if err := ssh.Unmarshal(nc.ExtraData(), &req); err != nil {
		_ = nc.Reject(ssh.ConnectionFailed, "")
		return
	}
	h.mu.Lock()
	h.forwards = append(h.forwards, net.JoinHostPort(req.Host, strconv.Itoa(int(req.Port))))
	h.mu.Unlock()
	target, err := net.Dial("tcp", h.addr.String())
	if err != nil {
		_ = nc.Reject(ssh.ConnectionFailed, "")
		return
	}
	ch, reqs, err := nc.Accept()
	if err != nil {
		_ = target.Close()
		return
	}
	go ssh.DiscardRequests(reqs)
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(ch, target); _ = ch.CloseWrite(); done <- struct{}{} }()
	go func() { _, _ = io.Copy(target, ch); done <- struct{}{} }()
	<-done
	_ = ch.Close()
	_ = target.Close()
	<-done
}

func (h *sshHost) session(nc ssh.NewChannel) {
	ch, reqs, err := nc.Accept()
	if err != nil {
		return
	}
	defer func() { _ = ch.Close() }()
	echo := func() {
		_, _ = io.Copy(ch, ch)
		_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
		_ = ch.Close()
	}
	for req := range reqs {
		switch req.Type {
		case "pty-req", "env", "window-change":
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
		case "shell":
			_ = req.Reply(true, nil)
			go echo()
		case "exec":
			var cmd struct{ Command string }
			if ssh.Unmarshal(req.Payload, &cmd) != nil {
				_ = req.Reply(false, nil)
				continue
			}
			h.mu.Lock()
			h.commands = append(h.commands, cmd.Command)
			h.mu.Unlock()
			_ = req.Reply(true, nil)
			if strings.HasPrefix(cmd.Command, "tmux new-session") {
				go echo()
				continue
			}
			go func() {
				if cmd.Command == "command -v tmux" {
					_, _ = io.WriteString(ch, "/usr/bin/tmux\n")
				}
				_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
				_ = ch.Close()
			}()
		default:
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}
}

func (h *sshHost) state() (conns int, commands, forwards []string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.conns, slices.Clone(h.commands), slices.Clone(h.forwards)
}

// terminalRig is the whole server with the test route table, an
// administrator, the in-process SSH host saved as a jump host and a
// realtime peer of the administrator.
type terminalRig struct {
	sys    *system
	admin  *http.Client
	base   string
	host   *sshHost
	user   principal.Principal
	peer   *protocoltest.Peer
	routes map[string]protocol.Route
	jumpID string
}

// newTerminalRig trusts the host key of the SSH host for the addresses in
// trusted: the loopback address (jump host and direct session) and the
// tailnet node behind the jump host.
func newTerminalRig(t *testing.T, trusted ...string) *terminalRig {
	t.Helper()
	var sys *system
	policy := tailnetTestPolicy(t, func() bool { return sys.tailnetRestricted() })
	sys, ts := openTestSystemWith(t, map[string]string{"ADMIN_PANEL_ENABLED": "true", "TMUX_ENABLED": "true"},
		func(*netpolicy.Policy) client.Network { return policy })
	sys.policy = policy
	r := &terminalRig{sys: sys, base: ts.URL, host: startSSHHost(t), user: principaltest.User(1), routes: map[string]protocol.Route{}}
	r.admin = signUp(t, ts.URL, "tailnetadmin", "tailnet-admin-password-1")
	r.set(t, false)
	ctx := t.Context()
	for _, h := range trusted {
		port := r.host.addr.Port
		if h == tailnetNode {
			port = 22
		}
		if err := sys.hostkeys.Record(ctx, r.user.UserID, h, port, r.host.key); err != nil {
			t.Fatal(err)
		}
	}
	saved, err := sys.hosts.SaveJumpHost(ctx, r.user.UserID, protocol.HostsJumpSave{
		Name: jsontext.Value(`"loopback jump"`), Host: jsontext.Value(`"127.0.0.1"`),
		Port: jsontext.Value(strconv.Itoa(r.host.addr.Port)), Username: jsontext.Value(`"jumper"`),
		AuthType: jsontext.Value(`"password"`)})
	if err != nil {
		t.Fatal(err)
	}
	var jump struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(saved, &jump); err != nil || jump.ID == "" {
		t.Fatalf("jump host %s: %v", saved, err)
	}
	r.jumpID = jump.ID
	r.peer = protocoltest.NewPeer(t, r.user)
	for _, route := range sys.terminal.Routes() {
		r.routes[route.Type] = route
	}
	return r
}

func (r *terminalRig) set(t *testing.T, restrict bool) {
	t.Helper()
	setTailnetBlock(t, r.admin, r.base, "tailnet-admin-password-1", restrict)
}

// viaJump is a tmux session to the tailnet node through the jump host.
func (r *terminalRig) viaJump() protocol.OpenTarget {
	return protocol.OpenTarget{Host: tailnetNode, Port: 22, JumpHostID: r.jumpID, JumpPassword: "pw"}
}

// direct is a tmux session to the SSH host on the loopback address.
func (r *terminalRig) direct() protocol.OpenTarget {
	return protocol.OpenTarget{Host: "127.0.0.1", Port: r.host.addr.Port}
}

// open runs terminal.open on channel ch and returns the session id.
func (r *terminalRig) open(ctx context.Context, ch uint32, target protocol.OpenTarget) (string, *protocol.Error) {
	target.AuthType, target.Password, target.Username, target.UseTmux = protocol.AuthPassword, "pw", "alice", true
	raw, perr := protocoltest.Call(ctx, r.routes[protocol.TypeTerminalOpen], r.peer, protocol.TerminalOpen{
		Ch: ch, RequestID: "open_" + strconv.Itoa(int(ch)), Rows: 24, Cols: 80, Target: target})
	if perr != nil {
		return "", perr
	}
	var opened protocol.TerminalOpened
	if err := json.Unmarshal(raw, &opened); err != nil {
		return "", &protocol.Error{Message: err.Error()}
	}
	return opened.SessionID, nil
}

func (r *terminalRig) mustOpen(t *testing.T, ch uint32, target protocol.OpenTarget) string {
	t.Helper()
	id, perr := r.open(t.Context(), ch, target)
	if perr != nil {
		t.Fatalf("terminal.open %d: %+v", ch, perr)
	}
	return id
}

// closedEvents are the terminal.closed events the owner received.
func (r *terminalRig) closedEvents(t *testing.T) []protocol.TerminalClosed {
	t.Helper()
	var told []protocol.TerminalClosed
	for _, ev := range r.peer.Events(protocol.TypeTerminalClosed) {
		var c protocol.TerminalClosed
		if err := json.Unmarshal(ev.Payload, &c); err != nil {
			t.Fatal(err)
		}
		told = append(told, c)
	}
	return told
}

// waitConns waits until the SSH host has want open connections.
func (r *terminalRig) waitConns(t *testing.T, want int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for conns, _, _ := r.host.state(); conns != want; conns, _, _ = r.host.state() {
		if time.Now().After(deadline) {
			t.Fatalf("%d SSH connections open, want %d", conns, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// W3-3/OP3-2 end to end: real SSH terminal sessions opened through the
// realtime routes of the whole server. Turning the tailnet block on in
// /admin/api/settings closes the tmux session that reaches a tailnet node
// through a loopback jump host, detached like an administrator disconnect:
// tmux keeps running, the session becomes restorable, the owner learns
// the reason once and its quota slot is free. The direct session to the
// loopback address stays open, and saving the block again closes nothing.
func TestTailnetBlockClosesTerminalSessions(t *testing.T) {
	r := newTerminalRig(t, "127.0.0.1", tailnetNode)
	sys := r.sys
	jumped := r.mustOpen(t, 1, r.viaJump())
	direct := r.mustOpen(t, 2, r.direct())
	conns, commands, forwards := r.host.state()
	tmux := 0
	for _, c := range commands {
		if strings.HasPrefix(c, "tmux new-session") {
			tmux++
		}
	}
	if conns != 3 || tmux != 2 || !slices.Equal(forwards, []string{tailnetNode + ":22"}) {
		t.Fatalf("before the block: %d connections, commands %q, forwards %v", conns, commands, forwards)
	}
	if st := sys.terminal.Stats(); st.Sessions != 2 || st.Reserved != 2 {
		t.Fatalf("before the block: %+v", st)
	}

	r.set(t, true)
	live := map[string]bool{}
	for _, s := range sys.terminal.AdminSessions() {
		live[s.ID] = true
	}
	if live[jumped] || !live[direct] {
		t.Fatalf("after the block: live %v, jumped %s, direct %s", live, jumped, direct)
	}
	told := r.closedEvents(t)
	if len(told) != 1 || told[0].SessionID != jumped || !strings.Contains(told[0].Reason, "requires Tailscale SSH") {
		t.Fatalf("owner was told %+v", told)
	}
	r.waitConns(t, 1)
	if _, commands, _ := r.host.state(); slices.ContainsFunc(commands, func(c string) bool { return strings.Contains(c, "kill-session") }) {
		t.Fatalf("tmux was killed: %q", commands)
	}
	restorable, err := sys.terminal.Persistent(t.Context(), r.user)
	if err != nil {
		t.Fatal(err)
	}
	if len(restorable) != 1 || restorable[0].SessionID != jumped || restorable[0].JumpHostID != r.jumpID {
		t.Fatalf("restorable %+v", restorable)
	}
	if st := sys.terminal.Stats(); st.Sessions != 1 || st.Reserved != 1 {
		t.Fatalf("after the block: %+v", st)
	}
	_, export := get(t, r.admin, r.base+"/admin/api/audit/export")
	if strings.Count(export, "TAILNET_RESTRICTED_CONNECTIONS_CLOSED") != 1 ||
		!strings.Contains(export, "ssh_sessions=1") || !strings.Contains(export, "pool_connections=0") {
		t.Fatalf("audit %s", export)
	}

	r.set(t, true)
	if st := sys.terminal.Stats(); st.Sessions != 1 || len(r.closedEvents(t)) != 1 {
		t.Fatalf("saving the block again: %+v", st)
	}
}

// openDuringBlock starts terminal.open of target, turns the tailnet block
// on while the host key prompt for promptHost is open, then trusts the
// key and returns the outcome of the open.
func (r *terminalRig) openDuringBlock(t *testing.T, target protocol.OpenTarget, promptHost string) (string, *protocol.Error) {
	t.Helper()
	type result struct {
		id   string
		perr *protocol.Error
	}
	done := make(chan result, 1)
	go func() {
		id, perr := r.open(t.Context(), 1, target)
		done <- result{id, perr}
	}()
	var prompt protocol.PromptHostKey
	deadline := time.Now().Add(10 * time.Second)
	for prompt.PromptID == "" {
		if time.Now().After(deadline) {
			t.Fatal("no host key prompt")
		}
		for _, ev := range r.peer.Events(protocol.TypePromptHostKey) {
			if err := json.Unmarshal(ev.Payload, &prompt); err != nil {
				t.Fatal(err)
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	if prompt.Host != promptHost {
		t.Fatalf("prompt %+v", prompt)
	}
	r.set(t, true)
	if _, perr := protocoltest.Call(t.Context(), r.routes[protocol.TypePromptAnswer], r.peer,
		protocol.PromptAnswer{PromptID: prompt.PromptID, Kind: protocol.PromptKindHostKey, Accepted: true}); perr != nil {
		t.Fatalf("answer: %+v", perr)
	}
	select {
	case res := <-done:
		return res.id, res.perr
	case <-time.After(10 * time.Second):
		t.Fatal("terminal.open did not return")
		return "", nil
	}
}

// A terminal.open that passed the network policy before the block was
// turned on and still waits for the user to trust the node's host key
// does not leave a session on the route the block now refuses; its quota
// slot is free and both connections end. Negative: a pending open on an
// allowed route still opens.
func TestTailnetBlockRefusesPendingTerminalOpen(t *testing.T) {
	r := newTerminalRig(t, "127.0.0.1")
	id, perr := r.openDuringBlock(t, r.viaJump(), tailnetNode)
	if perr == nil || !strings.Contains(perr.Message, "requires Tailscale SSH") {
		t.Fatalf("terminal.open on a refused route: session %q, error %+v", id, perr)
	}
	if st := r.sys.terminal.Stats(); st.Sessions != 0 || st.Reserved != 0 {
		t.Fatalf("after the refused open: %+v", st)
	}
	r.waitConns(t, 0)
}

func TestTailnetBlockKeepsPendingAllowedTerminalOpen(t *testing.T) {
	r := newTerminalRig(t)
	id, perr := r.openDuringBlock(t, r.direct(), "127.0.0.1")
	if perr != nil {
		t.Fatalf("terminal.open on an allowed route: %+v", perr)
	}
	if st := r.sys.terminal.Stats(); st.Sessions != 1 || st.Reserved != 1 || len(r.closedEvents(t)) != 0 {
		t.Fatalf("after the allowed open %s: %+v", id, st)
	}
	r.waitConns(t, 1)
}
