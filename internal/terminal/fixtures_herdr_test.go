//go:build e2e

package terminal

import (
	"context"
	"io"
	"testing"

	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
	"github.com/bifrost0x/webssh/internal/ssh/client"
	"github.com/bifrost0x/webssh/internal/ssh/remotecmd"
)

type nopExec struct{ id string }

func (nopExec) Exec(context.Context, string, io.Reader, io.Writer, io.Writer) (int, error) {
	return 0, nil
}

func TestHerdrFixtures(t *testing.T) {
	m := newLimited(t, 2, 1, Config{}, &fakeShells{})
	g := &grants{}
	g.overview.Store(true)
	g.session.Store(true)
	m.herdr = g
	m.profiles = fakeProfiles{
		"p1": {Owner: 1, Hop: client.Hop{Host: "a.example", Port: 2222, User: "dev"}},
		"p2": {Owner: 2, Hop: client.Hop{Host: "b.example", Port: 22, User: "dev"}},
	}
	peer := user(t, 1)
	exec := func(id string) remotecmd.Executor { return nopExec{id} }
	// Two fixtures although the session quota allows one: they do not count.
	ids, err := m.ReplaceHerdrFixtures(t.Context(), 1, []string{"p1", "p1"}, exec)
	if err != nil || len(ids) != 2 {
		t.Fatalf("fixtures: %v %v", ids, err)
	}
	restore, err := m.ReplaceFixtureSessions(t.Context(), peer, 1, 1)
	if err != nil || len(restore) != 1 {
		t.Fatal(err)
	}
	e, sc, ok := m.HerdrFixture(1, ids[0])
	if !ok || e.(nopExec).id != ids[0] || sc.Host != "a.example" || sc.Port != 2222 || sc.ProfileID != "p1" || !sc.Herdr || !sc.UseHerdr || sc.Done == nil {
		t.Fatalf("fixture = %v %+v %v", e, sc, ok)
	}
	if _, _, ok := m.HerdrFixture(2, ids[0]); ok {
		t.Fatal("another owner sees the fixture")
	}
	if _, _, ok := m.HerdrFixture(1, restore[0]); ok {
		t.Fatal("a restore fixture is a Herdr fixture")
	}
	var att protocol.TerminalAttached
	if werr := call(t, m, peer, protocol.TypeTerminalAttach, protocol.TerminalAttach{Ch: 5, SessionID: ids[0]}, &att); werr != nil {
		t.Fatal(werr)
	}
	if output(t, peer, 5) != herdrFixtureOutput {
		t.Fatalf("replay %q", output(t, peer, 5))
	}
	// A foreign profile fails the request; the earlier Herdr fixtures end
	// first, as in the Python fixture, and the restore fixture stays.
	if _, err := m.ReplaceHerdrFixtures(t.Context(), 1, []string{"p2"}, exec); err == nil {
		t.Fatal("foreign profile accepted")
	}
	list, _ := m.Restorable(t.Context(), principal.Principal{UserID: 1})
	if len(list) != 1 || list[0].SessionID != restore[0] {
		t.Fatalf("after replace: %+v", list)
	}
	g.session.Store(false)
	ids, err = m.ReplaceHerdrFixtures(t.Context(), 1, []string{"p1"}, exec)
	if err != nil || len(ids) != 1 {
		t.Fatal(err)
	}
	if _, sc, _ := m.HerdrFixture(1, ids[0]); !sc.Herdr || sc.UseHerdr {
		t.Fatalf("grants not applied: %+v", sc)
	}
	if _, err := m.ReplaceHerdrFixtures(t.Context(), 1, make([]string, 13), exec); err == nil {
		t.Fatal("more than 12 fixtures")
	}
}
