//go:build e2e

package terminal

import (
	"context"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
	"github.com/bifrost0x/webssh/internal/ssh/remotecmd"
)

// herdrFixtureOutput is the screen of a Herdr fixture session, as in
// tests/e2e/herdr_fixture.py.
const herdrFixtureOutput = "herdr fixture ready\r\n$ "

// ReplaceHerdrFixtures serves internal/e2eseed.HerdrSessions: it ends the
// owner's earlier Herdr fixtures and creates one connected session per
// saved host of the owner, whose commands run on exec(sessionID). The
// Herdr flags are decided as for a real connection (HerdrGrants). A
// profile the owner cannot resolve fails the request before anything is
// created. The sessions do not count against the session quota.
func (m *Manager) ReplaceHerdrFixtures(ctx context.Context, owner int64, profileIDs []string, exec func(sessionID string) remotecmd.Executor) ([]string, error) {
	if owner <= 0 || len(profileIDs) > maxFixtureSessions || exec == nil {
		return nil, fault.New(fault.InvalidValue, "")
	}
	for _, s := range m.sessionsOf(owner) {
		if s.fixtureExec != nil {
			s.terminate(reasonClosed, nil)
		}
	}
	if len(profileIDs) > 0 && m.profiles == nil {
		return nil, fault.New(fault.NotFound, "")
	}
	infos := make([]protocol.SessionInfo, 0, len(profileIDs))
	for _, id := range profileIDs {
		t, err := m.profiles.Resolve(ctx, owner, id)
		if err != nil {
			return nil, err
		}
		info := sessionInfo(t)
		info.ProfileID = id
		if m.herdr != nil {
			info.Herdr = m.herdr.Overview(ctx, owner, id)
			info.UseHerdr = info.Herdr && m.herdr.SessionMode(ctx, owner, id)
		}
		infos = append(infos, info)
	}
	ids := make([]string, 0, len(infos))
	for _, info := range infos {
		s := m.newSession(owner, newIdleShell(), info, nil)
		s.fixture = true
		s.fixtureExec = exec(s.id)
		s.seq = 1
		s.replay.add(chunk{seq: 1, data: []byte(herdrFixtureOutput)})
		if err := m.register(s, m.generation(owner)); err != nil {
			return ids, err
		}
		s.start(nil)
		ids = append(ids, s.id)
	}
	return ids, nil
}

// HerdrFixture returns the executor and the connection details of the
// owner's live Herdr fixture session id; ok is false for anything else.
func (m *Manager) HerdrFixture(owner int64, id string) (remotecmd.Executor, SessionConn, bool) {
	s, err := m.lookup(owner, id)
	if err != nil || s.fixtureExec == nil {
		return nil, SessionConn{}, false
	}
	info, live := s.snapshot()
	if !live {
		return nil, SessionConn{}, false
	}
	return s.fixtureExec, SessionConn{Done: s.done, ProfileID: info.ProfileID, Host: info.Host, Port: info.Port,
		Username: info.Username, Herdr: info.Herdr, UseHerdr: info.UseHerdr, Name: info.DisplayName, InputIdle: s.InputIdle}, true
}
