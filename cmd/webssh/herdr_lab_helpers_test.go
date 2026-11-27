//go:build herdr

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/bifrost0x/webssh/internal/hostops"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/principal/principaltest"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
	"github.com/bifrost0x/webssh/internal/realtime/protocol/protocoltest"
)

// Fixed commands of the lab checks. Herdr sits only where its installer
// puts it, outside the PATH of a non-login exec channel.
const (
	labHerdr        = `$HOME/.local/bin/herdr`
	labCountHerdr   = `cat /proc/[0-9]*/comm 2>/dev/null | grep -c -x herdr`
	labServerAnswer = labHerdr + ` api snapshot >/dev/null 2>&1`
)

// The command texts of the Python release (app/herdr.py), run directly on
// the host; hostops sends the same text (HerdrProbeCommand).
const (
	labPathPrefix     = `PATH="$PATH:$HOME/.local/bin:/usr/local/bin:/opt/homebrew/bin"`
	herdrProbeLine    = `sh -c '` + labPathPrefix + `; command -v herdr >/dev/null 2>&1'`
	herdrSnapshotLine = `sh -c '` + labPathPrefix + `; herdr api snapshot & p=$!; ` +
		`(sleep 5; kill "$p") >/dev/null 2>&1 & w=$!; ` +
		`wait "$p"; s=$?; kill "$w" >/dev/null 2>&1; exit "$s"` + `'`
)

// herdrLab is one run of the disposable Herdr host (run-go-lab.sh).
type herdrLab struct {
	host        string
	port        int
	password    string
	fingerprint string
}

func readHerdrLab(t *testing.T) herdrLab {
	t.Helper()
	addr, pw, fp := os.Getenv("WEBSSH_HERDR_ADDR"), os.Getenv("WEBSSH_HERDR_PASSWORD"), os.Getenv("WEBSSH_HERDR_FINGERPRINT")
	if addr == "" || pw == "" || !strings.HasPrefix(fp, "SHA256:") {
		t.Fatal("run tests/integration/herdr/run-go-lab.sh")
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	return herdrLab{host: host, port: n, password: pw, fingerprint: fp}
}

// side is a direct SSH connection to the lab host for setting up and
// checking Herdr next to WebSSH, as the Python lab test does with Paramiko.
type side struct {
	t *testing.T
	c *ssh.Client
}

func (l herdrLab) side(t *testing.T, user string) side {
	t.Helper()
	c, err := ssh.Dial("tcp", net.JoinHostPort(l.host, strconv.Itoa(l.port)), &ssh.ClientConfig{
		User: user, Auth: []ssh.AuthMethod{ssh.Password(l.password)}, Timeout: 10 * time.Second,
		HostKeyAlgorithms: []string{ssh.KeyAlgoED25519},
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			if ssh.FingerprintSHA256(key) != l.fingerprint {
				return errors.New("unexpected lab host key")
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return side{t, c}
}

// run runs command and returns its exit status and trimmed output.
func (s side) run(command string) (int, string) {
	s.t.Helper()
	sess, err := s.c.NewSession()
	if err != nil {
		s.t.Fatal(err)
	}
	defer sess.Close()
	var out bytes.Buffer
	sess.Stdout = &out
	err = sess.Run(command)
	var exit *ssh.ExitError
	switch {
	case err == nil:
		return 0, strings.TrimSpace(out.String())
	case errors.As(err, &exit):
		return exit.ExitStatus(), strings.TrimSpace(out.String())
	}
	s.t.Fatalf("%s: %v", command, err)
	return 0, ""
}

func (s side) must(command string) string {
	s.t.Helper()
	status, out := s.run(command)
	if status != 0 {
		s.t.Fatalf("%s: exit %d, %q", command, status, out)
	}
	return out
}

// waitFor polls command until its exit status is 0.
func (s side) waitFor(command, message string) {
	s.t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for status, _ := s.run(command); status != 0; status, _ = s.run(command) {
		if time.Now().After(deadline) {
			s.t.Fatal(message)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// stopHerdr ends the account's Herdr server and removes its state.
func (s side) stopHerdr() {
	s.t.Helper()
	s.run(labHerdr + ` server stop >/dev/null 2>&1; sleep 1; rm -rf "$HOME/.config/herdr"`)
	deadline := time.Now().Add(10 * time.Second)
	for _, n := s.run(labCountHerdr); n != "0"; _, n = s.run(labCountHerdr) {
		if time.Now().After(deadline) {
			s.t.Fatal("Herdr server did not stop")
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// count returns the number of Herdr processes of every account.
func (s side) count() string {
	s.t.Helper()
	_, n := s.run(labCountHerdr)
	return n
}

func (s side) startServer() {
	s.t.Helper()
	s.must(`nohup ` + labHerdr + ` server >/dev/null 2>&1 &`)
	s.waitFor(labServerAnswer, "Herdr server did not start")
}

// herdrSystem is the whole server with the Herdr integration switched on,
// its terminal routes and the snapshot route as wire_serverops mounts it.
type herdrSystem struct {
	t      *testing.T
	sys    *system
	lab    herdrLab
	owner  principal.Principal
	routes map[string]protocol.Route
}

func newHerdrSystem(t *testing.T, lab herdrLab) *herdrSystem {
	t.Helper()
	sys, _ := openTestSystem(t, nil)
	setHerdrSwitch(t, sys, true)
	diag := &hostops.Diagnostics{Sessions: liveSessions{sys.terminal}, Switches: serverSwitches{sys.settings},
		Herdr: herdrGrants{sys}, Log: sys.log, HerdrPerMinute: sys.cfg.Terminal.MaxConnectionsPerUser * 12}
	h := &herdrSystem{t: t, sys: sys, lab: lab, owner: principaltest.User(1), routes: map[string]protocol.Route{}}
	for _, r := range append(sys.terminal.Routes(), diag.Routes()...) {
		h.routes[r.Type] = r
	}
	return h
}

// saveHost saves a host of the owner for user with the Herdr options.
func (h *herdrSystem) saveHost(user string, overview, session bool) string {
	h.t.Helper()
	v := func(s string) jsontext.Value { return jsontext.Value(s) }
	save := protocol.HostsProfileSave{Name: v(`"lab ` + user + `"`), Host: v(strconv.Quote(h.lab.host)),
		Port: v(strconv.Itoa(h.lab.port)), Username: v(strconv.Quote(user)), AuthType: v(`"password"`),
		Herdr: v(strconv.FormatBool(overview)), UseHerdr: v(strconv.FormatBool(session))}
	out, err := h.sys.hosts.SaveProfile(h.t.Context(), h.owner.UserID, save)
	if err != nil {
		h.t.Fatal(err)
	}
	var saved struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(out, &saved); err != nil || saved.ID == "" {
		h.t.Fatalf("saved %s: %v", out, err)
	}
	return saved.ID
}

// herdrTerm is one open WebSSH terminal on its own peer, channel 1.
type herdrTerm struct {
	h      *herdrSystem
	peer   *protocoltest.Peer
	opened protocol.TerminalOpened
	acked  uint64
	asked  time.Time // last herdr.snapshot
}

// open runs terminal.open for the saved host and accepts only the lab's
// host key.
func (h *herdrSystem) open(profileID string, useHerdr bool) *herdrTerm {
	h.t.Helper()
	ctx := principal.With(h.t.Context(), h.owner)
	peer := protocoltest.NewPeer(h.t, h.owner)
	type outcome struct {
		raw  []byte
		werr *protocol.Error
	}
	done := make(chan outcome, 1)
	go func() {
		raw, werr := protocoltest.Call(ctx, h.routes[protocol.TypeTerminalOpen], peer, protocol.TerminalOpen{
			Ch: 1, RequestID: "herdr-lab", Rows: 48, Cols: 160, Target: protocol.OpenTarget{ProfileID: profileID,
				AuthType: protocol.AuthPassword, Password: h.lab.password, UseHerdr: useHerdr}})
		done <- outcome{raw, werr}
	}()
	answered := map[string]bool{}
	var res outcome
	for waiting := true; waiting; {
		select {
		case res = <-done:
			waiting = false
		case <-time.After(20 * time.Millisecond):
		}
		for _, ev := range peer.Events(protocol.TypePromptHostKey) {
			var q protocol.PromptHostKey
			if err := json.Unmarshal(ev.Payload, &q); err != nil {
				h.t.Fatal(err)
			}
			if answered[q.PromptID] {
				continue
			}
			answered[q.PromptID] = true
			if _, werr := protocoltest.Call(ctx, h.routes[protocol.TypePromptAnswer], peer, protocol.PromptAnswer{
				PromptID: q.PromptID, Kind: protocol.PromptKindHostKey, Accepted: q.Fingerprint == h.lab.fingerprint}); werr != nil {
				h.t.Fatalf("answer: %+v", werr)
			}
		}
	}
	if res.werr != nil {
		h.t.Fatalf("terminal.open: %+v", res.werr)
	}
	term := &herdrTerm{h: h, peer: peer}
	if err := json.Unmarshal(res.raw, &term.opened); err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() { term.close() })
	return term
}

// screen joins the output of channel 1 and acknowledges it, so the
// session keeps sending.
func (term *herdrTerm) screen() string {
	var b strings.Builder
	var last uint64
	for _, f := range term.peer.Frames() {
		// Output frames: kind, flags, channel (4), sequence (8), data.
		if len(f) >= protocol.HeaderLen && protocol.Kind(f[0]) == protocol.KindOutput && binary.BigEndian.Uint32(f[2:6]) == 1 {
			b.Write(f[protocol.HeaderLen:])
			last = binary.BigEndian.Uint64(f[6:14])
		}
	}
	if last > term.acked {
		term.acked = last
		_ = term.h.sys.terminal.HandleBinary(term.peer, protocol.AppendFrame(nil, protocol.Frame{Kind: protocol.KindAck, Channel: 1, Seq: last}))
	}
	return b.String()
}

func (term *herdrTerm) waitOutput(want string) {
	term.h.t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for !strings.Contains(term.screen(), want) {
		if time.Now().After(deadline) {
			s := term.screen()
			term.h.t.Fatalf("%q not received; got %q", want, s[max(0, len(s)-400):])
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (term *herdrTerm) input(seq uint64, data string) {
	term.h.t.Helper()
	if err := term.h.sys.terminal.HandleBinary(term.peer, protocol.AppendFrame(nil, protocol.Frame{Kind: protocol.KindInput,
		Channel: 1, Seq: seq, Data: []byte(data)})); err != nil {
		term.h.t.Fatal(err)
	}
}

// reattach detaches the session from its peer and attaches it to a new
// one from the start of the replay, as a reloaded page does.
func (term *herdrTerm) reattach() *herdrTerm {
	h := term.h
	h.t.Helper()
	ctx := principal.With(h.t.Context(), h.owner)
	if _, werr := protocoltest.Call(ctx, h.routes[protocol.TypeTerminalDetach], term.peer, protocol.ChannelRef{Ch: 1}); werr != nil {
		h.t.Fatalf("detach: %+v", werr)
	}
	next := &herdrTerm{h: h, peer: protocoltest.NewPeer(h.t, h.owner), opened: term.opened, asked: term.asked}
	if _, werr := protocoltest.Call(ctx, h.routes[protocol.TypeTerminalAttach], next.peer,
		protocol.TerminalAttach{Ch: 1, SessionID: term.opened.SessionID}); werr != nil {
		h.t.Fatalf("attach: %+v", werr)
	}
	return next
}

// close runs terminal.close; closing an already closed session is fine.
func (term *herdrTerm) close() {
	ctx := principal.With(context.Background(), term.h.owner)
	_, _ = protocoltest.Call(ctx, term.h.routes[protocol.TypeTerminalClose], term.peer,
		protocol.SessionRef{SessionID: term.opened.SessionID})
}

// snapshot runs herdr.snapshot for the session as its owner.
func (term *herdrTerm) snapshot() protocol.HerdrResult {
	term.h.t.Helper()
	ctx := principal.With(term.h.t.Context(), term.h.owner)
	term.asked = time.Now()
	raw, werr := protocoltest.Call(ctx, term.h.routes[protocol.TypeHerdrSnapshot], term.peer,
		protocol.HerdrSnapshot{SessionID: term.opened.SessionID})
	if werr != nil {
		term.h.t.Fatalf("herdr.snapshot: %+v", werr)
	}
	var res protocol.HerdrResult
	if err := json.Unmarshal(raw, &res); err != nil {
		term.h.t.Fatal(err)
	}
	return res
}

// snapshotAfterPacing asks again once the per-session pacing (four
// seconds between snapshots) allows it.
func (term *herdrTerm) snapshotAfterPacing() protocol.HerdrResult {
	term.h.t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		res := term.snapshot()
		if reason(res) != "busy" || time.Now().After(deadline) {
			return res
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// awaitPacing sleeps until the per-session pacing (four seconds between
// snapshots) admits the next one.
func (term *herdrTerm) awaitPacing() {
	time.Sleep(time.Until(term.asked.Add(4*time.Second + 200*time.Millisecond)))
}

func reason(res protocol.HerdrResult) string {
	if res.Reason == nil {
		return ""
	}
	return *res.Reason
}
