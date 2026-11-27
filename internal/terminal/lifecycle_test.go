package terminal

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
	"github.com/bifrost0x/webssh/internal/ssh/client"
)

func TestSessionQuota(t *testing.T) {
	m := newLimited(t, 3, 2, Config{}, &fakeShells{})
	a, b, c := user(t, 1), user(t, 2), user(t, 3)
	open(t, m, a, 1)
	open(t, m, a, 2)
	if werr := call(t, m, a, protocol.TypeTerminalOpen, openReq(3, "x"), nil); werr == nil || werr.Code != fault.Busy {
		t.Fatalf("third session of a user: %+v", werr)
	}
	open(t, m, b, 1)
	if werr := call(t, m, c, protocol.TypeTerminalOpen, openReq(1, "x"), nil); werr == nil || werr.Code != fault.Busy {
		t.Fatalf("session above the global limit: %+v", werr)
	}
	// Closing a session frees its slot.
	id := m.sessionsOf(1)[0].id
	if werr := call(t, m, a, protocol.TypeTerminalClose, protocol.SessionRef{SessionID: id}, nil); werr != nil {
		t.Fatal(werr)
	}
	open(t, m, c, 1)
	if st := m.Stats(); st.Reserved != 3 || st.Sessions != 3 {
		t.Fatalf("stats %+v", st)
	}
}

// A failed attempt gives its quota slot and channel back.
func TestFailedOpenReleases(t *testing.T) {
	shells := &fakeShells{before: func(context.Context, client.Interaction) error {
		return fault.New(fault.AuthFailed, "")
	}}
	m := newLimited(t, 2, 1, Config{}, shells)
	peer := user(t, 1)
	for range 3 {
		if werr := call(t, m, peer, protocol.TypeTerminalOpen, openReq(1, "r"), nil); werr == nil || werr.Code != fault.AuthFailed {
			t.Fatalf("open: %+v", werr)
		}
	}
	if st := m.Stats(); st.Reserved != 0 || st.Attachments != 0 {
		t.Fatalf("stats after failures %+v", st)
	}
}

func TestOpenValidation(t *testing.T) {
	m := newManager(t, Config{}, &fakeShells{})
	peer := user(t, 1)
	mod := func(f func(*protocol.OpenTarget)) protocol.TerminalOpen {
		r := openReq(1, "r")
		f(&r.Target)
		return r
	}
	for name, tc := range map[string]struct {
		req  protocol.TerminalOpen
		code fault.Code
	}{
		"no user":        {mod(func(o *protocol.OpenTarget) { o.Username = " " }), fault.InvalidValue},
		"bad user":       {mod(func(o *protocol.OpenTarget) { o.Username = "a b" }), fault.InvalidValue},
		"gateway":        {mod(func(o *protocol.OpenTarget) { o.Username = "a:b" }), fault.NotAvailableInPreview},
		"no password":    {mod(func(o *protocol.OpenTarget) { o.Password = "" }), fault.InvalidValue},
		"no key":         {mod(func(o *protocol.OpenTarget) { o.AuthType = "key" }), fault.InvalidValue},
		"saved jump":     {mod(func(o *protocol.OpenTarget) { o.JumpHostID = "j1" }), fault.NotAvailableInPreview},
		"jump and socks": {mod(func(o *protocol.OpenTarget) { o.JumpHostID = "j1"; o.SOCKSProxyID = "s1" }), fault.InvalidValue},
		"profile":        {mod(func(o *protocol.OpenTarget) { o.ProfileID = "p1" }), fault.NotAvailableInPreview},
		"bad channel":    {protocol.TerminalOpen{Ch: 0, RequestID: "r", Target: protocol.OpenTarget{Host: "h", AuthType: "password"}}, fault.InvalidRequest},
	} {
		if werr := call(t, m, peer, protocol.TypeTerminalOpen, tc.req, nil); werr == nil || werr.Code != tc.code {
			t.Errorf("%s: %+v, want %s", name, werr, tc.code)
		}
	}
}

func TestOpenProfile(t *testing.T) {
	shells := &fakeShells{}
	m, err := New(Config{}, Deps{Shells: shells, Quotas: testQuotas(t, 10, 5), Log: newManager(t, Config{}, shells).log, Profiles: fakeProfiles{
		"p1": {Owner: 1, Hop: client.Hop{Host: "saved", Port: 2222, User: "alice"},
			Jumps:   []client.Hop{{Host: "bastion", Port: 22, User: "j", Auth: client.Auth{KeyID: "k"}}},
			Display: client.Display{JumpHostID: "j1", UseHerdr: true}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Shutdown(context.Background()) })
	peer := user(t, 1)
	req := openReq(1, "r")
	req.Target.ProfileID = "p1"
	req.Target.Password = "typed"
	var res protocol.TerminalOpened
	if werr := call(t, m, peer, protocol.TypeTerminalOpen, req, &res); werr != nil {
		t.Fatal(werr)
	}
	got := shells.targets[len(shells.targets)-1]
	if got.Hop.Host != "saved" || got.Hop.Auth.Password != "typed" || got.Owner != 1 {
		t.Fatalf("target %+v", got)
	}
	if i := res.Info; i.ProfileID != "p1" || i.ViaJump != "bastion" || i.JumpHostID != "j1" || i.Port != 2222 {
		t.Fatalf("info %+v", i)
	}
	// The saved host asks for Herdr, but nothing grants it: the login
	// shell runs, without a notice.
	if res.Info.Herdr || res.Info.UseHerdr {
		t.Fatalf("herdr without a grant: %+v", res.Info)
	}
	// Another user's profile does not resolve.
	if werr := call(t, m, user(t, 2), protocol.TypeTerminalOpen, req, nil); werr == nil || werr.Code != fault.NotFound {
		t.Fatalf("foreign profile: %+v", werr)
	}
}

// waitPrompt returns the first prompt event of type typ.
func waitPrompt(t *testing.T, peer *peerT, typ string) protocolEvent {
	t.Helper()
	var ev []protocolEvent
	eventually(t, typ, func() bool { ev = peer.Events(typ); return len(ev) > 0 })
	return ev[0]
}

func TestPrompts(t *testing.T) {
	var accepted, bannerOK bool
	shells := &fakeShells{before: func(ctx context.Context, ix client.Interaction) error {
		ok, err := ix.HostKey(ctx, client.HostKeyPrompt{Role: client.RoleJump, Host: "b", Port: 22, KeyType: "ssh-ed25519", Fingerprint: "SHA256:x"})
		if err != nil {
			return err
		}
		accepted = ok
		if !ok {
			return fault.New(fault.HostKeyNotAccepted, "")
		}
		bannerOK, err = ix.Banner(ctx, client.BannerPrompt{Role: client.RoleTarget, Host: "h", Port: 22, Banner: "hi"})
		if err != nil || !bannerOK {
			return fault.New(fault.BannerDeclined, "")
		}
		return nil
	}}
	m := newManager(t, Config{PromptTimeout: 300 * time.Millisecond}, shells)
	peer := user(t, 1)
	done := make(chan *protocol.Error, 1)
	go func() { done <- call(t, m, peer, protocol.TypeTerminalOpen, openReq(1, "req-1"), nil) }()

	hk := decode[protocol.PromptHostKey](t, waitPrompt(t, peer, protocol.TypePromptHostKey))
	if hk.RequestID != "req-1" || hk.Context != "jump_host" || hk.Fingerprint != "SHA256:x" || len(hk.PromptID) != 32 {
		t.Fatalf("host key prompt %+v", hk)
	}
	// Only the asking connection of the same user can answer, with the
	// right kind.
	other := user(t, 1)
	for _, try := range []struct {
		peer *peerT
		kind string
	}{{other, "host_key"}, {peer, "banner"}} {
		if werr := call(t, m, try.peer, protocol.TypePromptAnswer, protocol.PromptAnswer{PromptID: hk.PromptID, Kind: try.kind, Accepted: true}, nil); werr == nil || werr.Code != fault.NotFound {
			t.Fatalf("answer from %v/%s: %+v", try.peer.ID(), try.kind, werr)
		}
	}
	if werr := call(t, m, peer, protocol.TypePromptAnswer, protocol.PromptAnswer{PromptID: hk.PromptID, Kind: "host_key", Accepted: true}, nil); werr != nil {
		t.Fatal(werr)
	}
	if werr := call(t, m, peer, protocol.TypePromptAnswer, protocol.PromptAnswer{PromptID: hk.PromptID, Kind: "host_key", Accepted: true}, nil); werr == nil {
		t.Fatal("a prompt was answered twice")
	}
	// The banner is not answered and expires: declined.
	waitPrompt(t, peer, protocol.TypePromptBanner)
	if werr := <-done; werr == nil || werr.Code != fault.BannerDeclined || !accepted || bannerOK {
		t.Fatalf("open after expired banner: %+v", werr)
	}
	if closed := peer.Events(protocol.TypePromptClosed); len(closed) != 2 {
		t.Fatalf("%d prompt.closed, want one per prompt", len(closed))
	}
	if n := len(m.prompts.pending); n != 0 {
		t.Fatalf("%d prompts left", n)
	}
}

func TestCancel(t *testing.T) {
	gate := make(chan struct{})
	shells := &fakeShells{before: func(ctx context.Context, _ client.Interaction) error {
		select {
		case <-gate:
			return nil
		case <-ctx.Done():
			return fault.Wrap(fault.Cancelled, ctx.Err(), "")
		}
	}}
	m := newManager(t, Config{}, shells)
	peer := user(t, 1)
	if werr := call(t, m, peer, protocol.TypeTerminalCancel, protocol.TerminalCancel{RequestID: "none"}, nil); werr == nil || werr.Code != fault.NotFound {
		t.Fatalf("cancel without attempt: %+v", werr)
	}
	done := make(chan *protocol.Error, 1)
	go func() { done <- call(t, m, peer, protocol.TypeTerminalOpen, openReq(1, "r1"), nil) }()
	eventually(t, "attempt", func() bool { m.mu.Lock(); defer m.mu.Unlock(); return len(m.attempts) == 1 })
	// The same request id on the same connection is refused while running;
	// another connection cannot cancel it.
	if werr := call(t, m, peer, protocol.TypeTerminalOpen, openReq(2, "r1"), nil); werr == nil || werr.Code != fault.Busy {
		t.Fatalf("duplicate request id: %+v", werr)
	}
	if werr := call(t, m, user(t, 1), protocol.TypeTerminalCancel, protocol.TerminalCancel{RequestID: "r1"}, nil); werr == nil || werr.Code != fault.NotFound {
		t.Fatalf("cancel from another connection: %+v", werr)
	}
	if werr := call(t, m, peer, protocol.TypeTerminalCancel, protocol.TerminalCancel{RequestID: "r1"}, nil); werr != nil {
		t.Fatal(werr)
	}
	if werr := <-done; werr == nil || werr.Code != fault.Cancelled {
		t.Fatalf("cancelled open: %+v", werr)
	}
	if st := m.Stats(); st.Reserved != 0 || st.Sessions != 0 {
		t.Fatalf("stats %+v", st)
	}
	// After the commit a cancel reports conflict.
	close(gate)
	att := &attempt{owner: 1, cancel: func() {}}
	m.attempts[attemptKey{peer: peer.ID(), requestID: "r2"}] = att
	m.commit(att)
	if werr := call(t, m, peer, protocol.TypeTerminalCancel, protocol.TerminalCancel{RequestID: "r2"}, nil); werr == nil || werr.Code != fault.Conflict {
		t.Fatalf("cancel after commit: %+v", werr)
	}
}

// terminal.close reaches every connection the session is attached to and
// the requester; discard_late does the same with its own reason.
func TestCloseNotifies(t *testing.T) {
	m := newManager(t, Config{}, &fakeShells{})
	a, b, requester := user(t, 1), user(t, 1), user(t, 1)
	res := open(t, m, a, 1)
	if werr := call(t, m, b, protocol.TypeTerminalAttach, protocol.TerminalAttach{Ch: 1, SessionID: res.SessionID}, nil); werr != nil {
		t.Fatal(werr)
	}
	if werr := call(t, m, user(t, 2), protocol.TypeTerminalClose, protocol.SessionRef{SessionID: res.SessionID}, nil); werr == nil || werr.Code != fault.NotFound {
		t.Fatalf("foreign close: %+v", werr)
	}
	if werr := call(t, m, requester, protocol.TypeTerminalClose, protocol.SessionRef{SessionID: res.SessionID}, nil); werr != nil {
		t.Fatal(werr)
	}
	for _, p := range []*peerT{a, b, requester} {
		ev := p.Events(protocol.TypeTerminalClosed)
		if len(ev) != 1 || decode[protocol.TerminalClosed](t, ev[0]).Reason != reasonUser {
			t.Fatalf("peer %d: %v", p.ID(), ev)
		}
	}
	res = open(t, m, a, 2)
	if werr := call(t, m, a, protocol.TypeTerminalDiscardLate, protocol.SessionRef{SessionID: res.SessionID, RequestID: "rc"}, nil); werr != nil {
		t.Fatal(werr)
	}
	if ev := a.Events(protocol.TypeTerminalClosed); len(ev) != 2 || decode[protocol.TerminalClosed](t, ev[1]).Reason != reasonDiscarded {
		t.Fatalf("discard: %v", ev)
	}
}

func TestRenameAndRestorable(t *testing.T) {
	m := newManager(t, Config{}, &fakeShells{})
	peer := user(t, 1)
	res := open(t, m, peer, 1)
	name := "  " + strings.Repeat("ä", 130) + " "
	if werr := call(t, m, peer, protocol.TypeTerminalRename, protocol.TerminalRename{SessionID: res.SessionID, Name: name}, nil); werr != nil {
		t.Fatal(werr)
	}
	list, _ := m.Restorable(t.Context(), principal.Principal{UserID: 1})
	if len(list) != 1 || list[0].DisplayName != strings.Repeat("ä", 128) || list[0].SessionID != res.SessionID {
		t.Fatalf("restorable %+v", list)
	}
	if list, _ := m.Restorable(t.Context(), principal.Principal{UserID: 2}); len(list) != 0 {
		t.Fatal("another user's sessions listed")
	}
	if werr := call(t, m, user(t, 2), protocol.TypeTerminalRename, protocol.TerminalRename{SessionID: res.SessionID, Name: "x"}, nil); werr == nil {
		t.Fatal("foreign rename")
	}
}

func TestIdleTimeout(t *testing.T) {
	m := newManager(t, Config{IdleTimeout: 300 * time.Millisecond, IdleWarning: 200 * time.Millisecond, SweepEvery: 10 * time.Millisecond}, &fakeShells{})
	peer := user(t, 1)
	res := open(t, m, peer, 1)
	eventually(t, "warning", func() bool { return len(peer.Events(protocol.TypeTerminalTimeoutWarn)) == 1 })
	// Activity re-arms the warning.
	m.Keepalive(peer)
	if _, err := m.lookup(1, res.SessionID); err != nil {
		t.Fatal("keepalive did not keep the session")
	}
	eventually(t, "second warning", func() bool { return len(peer.Events(protocol.TypeTerminalTimeoutWarn)) == 2 })
	eventually(t, "timeout", func() bool { return len(peer.Events(protocol.TypeTerminalClosed)) == 1 })
	if w := decode[protocol.TerminalTimeoutWarning](t, peer.Events(protocol.TypeTerminalTimeoutWarn)[0]); w.SessionID != res.SessionID {
		t.Fatalf("warning %+v", w)
	}
}

// A revocation that signs the user out ends the user's SSH sessions and
// connection attempts at once; ending another login does not.
func TestRevocation(t *testing.T) {
	gate := make(chan struct{})
	shells := &fakeShells{}
	m := newManager(t, Config{}, shells)
	peer := user(t, 1)
	open(t, m, peer, 1)
	sh := shells.last(t)
	other := user(t, 2)
	open(t, m, other, 1)

	m.Revoked(principal.Revocation{SessionID: "s", UserID: 1, Reason: principal.ReasonRevokedByUser})
	if len(m.sessionsOf(1)) != 1 {
		t.Fatal("ending another login closed the terminals")
	}
	shells.before = func(ctx context.Context, _ client.Interaction) error {
		select {
		case <-gate:
		case <-ctx.Done():
		}
		return fault.Wrap(fault.Cancelled, ctx.Err(), "")
	}
	done := make(chan *protocol.Error, 1)
	go func() { done <- call(t, m, peer, protocol.TypeTerminalOpen, openReq(2, "r2"), nil) }()
	eventually(t, "attempt", func() bool { m.mu.Lock(); defer m.mu.Unlock(); return len(m.attempts) == 1 })

	m.Revoked(principal.Revocation{SessionID: "s", UserID: 1, Reason: principal.ReasonLogout})
	if len(m.sessionsOf(1)) != 0 || len(peer.Events(protocol.TypeTerminalClosed)) != 1 {
		t.Fatal("sign-out did not end the session at once")
	}
	eventually(t, "shell closed", sh.isClosed)
	if werr := <-done; werr == nil || werr.Code != fault.Cancelled {
		t.Fatalf("attempt after sign-out: %+v", werr)
	}
	if len(m.sessionsOf(2)) != 1 {
		t.Fatal("another user's session ended")
	}
	close(gate)
}

// A connection whose context ended (revoked or closed) forwards no input,
// even before OnClose ran (condition K6).
func TestInputAfterPeerContextEnds(t *testing.T) {
	shells := &fakeShells{}
	m := newManager(t, Config{}, shells)
	peer := user(t, 1)
	open(t, m, peer, 1)
	peer.Close()
	if err := m.HandleBinary(peer, input(1, 1, "rm -rf ~\r", false)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	if got := shells.last(t).typed(); got != "" {
		t.Fatalf("input forwarded after the connection ended: %q", got)
	}
	m.PeerClosed(peer)
	if st := m.Stats(); st.Attachments != 0 || st.Sessions != 1 {
		t.Fatalf("after close %+v", st)
	}
	// Opening on a closed connection creates nothing.
	if werr := call(t, m, peer, protocol.TypeTerminalOpen, openReq(2, "x"), nil); werr == nil {
		t.Fatal("open on a closed connection")
	}
	if len(m.peers) != 0 {
		t.Fatal("state recreated for a closed connection")
	}
}

func TestShellEndCloses(t *testing.T) {
	shells := &fakeShells{}
	m := newManager(t, Config{}, shells)
	peer := user(t, 1)
	open(t, m, peer, 1)
	sh := shells.last(t)
	sh.push(t, "bye")
	_ = sh.Close()
	eventually(t, "closed", func() bool { return len(peer.Events(protocol.TypeTerminalClosed)) == 1 })
	if output(t, peer, 1) != "bye" || m.Stats().Reserved != 0 {
		t.Fatal("last output lost or slot kept")
	}
}

func TestResize(t *testing.T) {
	shells := &fakeShells{}
	m := newManager(t, Config{}, shells)
	peer := user(t, 1)
	open(t, m, peer, 1)
	if werr := call(t, m, peer, protocol.TypeTerminalResize, protocol.TerminalResize{Ch: 1, Rows: 9999, Cols: 0}, nil); werr != nil {
		t.Fatal(werr)
	}
	sh := shells.last(t)
	eventually(t, "resize", func() bool { sh.mu.Lock(); defer sh.mu.Unlock(); return len(sh.sizes) == 1 })
	if sh.sizes[0] != [2]int{500, 80} {
		t.Fatalf("size %v", sh.sizes[0])
	}
	if werr := call(t, m, peer, protocol.TypeTerminalResize, protocol.TerminalResize{Ch: 9, Rows: 1, Cols: 1}, nil); werr == nil {
		t.Fatal("resize of an unbound channel")
	}
}
