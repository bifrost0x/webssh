package terminal

import (
	"bytes"
	"context"
	"slices"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
	"github.com/bifrost0x/webssh/internal/ssh/client"
)

// endMode says what happens to a session's tmux session when the terminal
// session ends. Sessions without tmux ignore it.
type endMode int

const (
	// endDetach leaves tmux running for a later reattach: idle timeout,
	// sign-out, server shutdown.
	endDetach endMode = iota
	// endProbe follows the end of the shell: the row stays only while
	// tmux still runs on the host (or that cannot be told).
	endProbe
	// endKill is the user closing the tab: tmux ends unless another live
	// session of the user is attached to it (a reconnect that replaced
	// this one).
	endKill
	// endDiscard abandons an attempt: a new tmux session ends, a
	// reattached one stays.
	endDiscard
	// endRevoke ends tmux after access was revoked and reports a kill
	// that was not confirmed.
	endRevoke
)

// tmuxGone are the tmux errors that mean the session no longer exists.
var tmuxGone = [][]byte{[]byte("can't find session"), []byte("no server running"), []byte("session not found")}

// finish runs in the background after a session ended: it settles tmux,
// then closes the shell and its connection.
func (m *Manager) finish(id string, owner int64, sh client.Shell, tm *tmuxBinding, end endMode) {
	if tm != nil {
		m.endTmux(id, owner, tm, end)
	}
	if err := sh.Close(); err != nil {
		m.log.Debug("terminal shell close", "session", id, "err", err)
	}
}

func (m *Manager) endTmux(id string, owner int64, tm *tmuxBinding, end endMode) {
	ctx, cancel := context.WithTimeout(context.Background(), tmuxEndTimeout)
	defer cancel()
	keep := true
	switch end {
	case endProbe:
		line, err := tmuxTargetCommand("has-session", tm.name)
		if err == nil {
			var status int
			status, _, err = tm.host.run(ctx, line, tmuxCmdTimeout)
			keep = err != nil || status == 0
		}
	case endKill, endRevoke:
		keep = false
		if m.tmuxShared(id, owner, tm.name) {
			break
		}
		if !m.killTmux(ctx, tm) && end == endRevoke {
			// The transport was gone or the kill did not finish, so the
			// tmux session may still run (Python: TMUX_SESSION_NOT_ENDED).
			m.tmuxNotEnded("user_id", owner, "reason", "kill_unconfirmed", "tmux_session", tm.name)
		}
	case endDiscard:
		if !tm.reattach {
			keep = false
			m.killTmux(ctx, tm)
		}
	}
	if !tm.recorded {
		return
	}
	var err error
	if keep {
		err = m.store.detached(ctx, id, m.now())
	} else {
		err = m.store.remove(ctx, id)
	}
	if err != nil {
		m.log.Error("persistent tmux session not updated", "session", id, "err", err)
	}
}

// killTmux ends the tmux session; true when it is confirmed gone.
func (m *Manager) killTmux(ctx context.Context, tm *tmuxBinding) bool {
	line, err := tmuxTargetCommand("kill-session", tm.name)
	if err != nil {
		return false
	}
	status, stderr, err := tm.host.run(ctx, line, tmuxCmdTimeout)
	if err != nil {
		m.log.Debug("tmux kill-session failed", "tmux_session", tm.name, "err", err)
		return false
	}
	return status == 0 || slices.ContainsFunc(tmuxGone, func(marker []byte) bool { return bytes.Contains(stderr, marker) })
}

// tmuxShared reports whether another live session of owner runs the same
// tmux session.
func (m *Manager) tmuxShared(id string, owner int64, name string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, s := range m.sessions {
		if s.id != id && s.owner == owner && s.tmux != nil && s.tmux.name == name {
			return true
		}
	}
	return false
}

// recordTmux stores the row of a new tmux session before the session
// becomes visible. A failed write leaves the session running without a
// reconnect offer, as the Python release did; it is logged.
func (m *Manager) recordTmux(s *Session) {
	info, tm := s.info, s.tmux
	now := m.now()
	row := PersistentRow{
		SessionID: s.id, UserID: s.owner, Host: info.Host, Port: int64(info.Port), Username: info.Username,
		KeyID: nullable(info.KeyID), AuthType: info.AuthType, TmuxSessionName: tm.name,
		DisplayName: nullable(info.DisplayName), JumpHostID: nullable(info.JumpHostID),
		SOCKSProxyID: nullable(info.SOCKSProxyID), ViaSOCKS: info.ViaSOCKS, ProfileID: nullable(info.ProfileID),
		ViaJump: nullable(info.ViaJump), ReconnectRouteKnown: info.ReconnectRouteKnown, Connected: true,
		CreatedAt: pyTime(now), LastActivity: pyTime(now),
	}
	ctx, cancel := context.WithTimeout(context.Background(), tmuxEndTimeout)
	defer cancel()
	if err := m.store.record(ctx, row, tm.reattach); err != nil {
		m.log.Error("persistent tmux session not recorded", "session", s.id, "err", err)
		return
	}
	tm.recorded = true
}

// withTmux adds the tmux fields to a new session's description.
func withTmux(info protocol.SessionInfo, tm *tmuxBinding, plan tmuxPlan) protocol.SessionInfo {
	if tm == nil {
		return info
	}
	info.UseTmux, info.TmuxSessionName, info.DisplayName = true, tm.name, displayName(plan.displayName)
	return info
}

// Persistent lists the persistent tmux sessions of p that no live session
// runs, oldest first: the reconnect offer of the page
// (persistent_session_available). Empty while tmux is switched off.
func (m *Manager) Persistent(ctx context.Context, p principal.Principal) ([]protocol.SessionInfo, error) {
	if !m.tmuxOn(ctx) {
		return nil, nil
	}
	rows, err := m.store.ofUser(ctx, p.UserID)
	if err != nil {
		return nil, fault.Wrap(fault.StorageError, err, "")
	}
	live := map[string]bool{}
	for _, s := range m.sessionsOf(p.UserID) {
		live[s.id] = true
	}
	out := make([]protocol.SessionInfo, 0, len(rows))
	for _, r := range rows {
		if live[r.SessionID] {
			continue
		}
		out = append(out, protocol.SessionInfo{
			SessionID: r.SessionID, Host: r.Host, Port: int(r.Port), Username: r.Username,
			AuthType: r.AuthType, KeyID: r.KeyID.String, ProfileID: r.ProfileID.String,
			ViaJump: r.ViaJump.String, JumpHostID: r.JumpHostID.String, SOCKSProxyID: r.SOCKSProxyID.String,
			ViaSOCKS: r.ViaSOCKS, ReconnectRouteKnown: r.ReconnectRouteKnown, UseTmux: true,
			TmuxSessionName: r.TmuxSessionName, DisplayName: r.DisplayName.String,
		})
	}
	return out, nil
}

// maxUsageLabels is the number of sessions named in a refusal (Python: 20).
const maxUsageLabels = 20

// UsingSOCKSProxy counts the persistent sessions of owner that need the
// SOCKS5 proxy for a reattach (hosts.PersistentSessions). The labels are
// display names or user@host of the first 20.
func (m *Manager) UsingSOCKSProxy(ctx context.Context, owner int64, proxyID string) (int, []string, error) {
	if m.store.db == nil {
		return 0, nil, nil
	}
	rows, err := m.store.ofUser(ctx, owner)
	if err != nil {
		return 0, nil, err
	}
	count, labels := 0, []string{}
	for _, r := range rows {
		if !r.SOCKSProxyID.Valid || r.SOCKSProxyID.String != proxyID {
			continue
		}
		count++
		if len(labels) < maxUsageLabels {
			label := r.DisplayName.String
			if label == "" {
				label = r.Username + "@" + r.Host
			}
			labels = append(labels, label)
		}
	}
	return count, labels, nil
}

// forgetUser removes every persistent session of owner after access was
// revoked and reports those no live connection could end.
func (m *Manager) forgetUser(owner int64, live []string) {
	if m.store.db == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), tmuxEndTimeout)
	defer cancel()
	rows, err := m.store.removeUser(ctx, owner)
	if err != nil {
		m.log.Error("persistent tmux sessions not removed", "user_id", owner, "err", err)
		return
	}
	for _, r := range rows {
		if !slices.Contains(live, r.SessionID) {
			m.tmuxNotEnded("user_id", owner, "reason", "detached", "host", r.Host, "port", r.Port, "ssh_user", r.Username,
				"tmux_session", r.TmuxSessionName)
		}
	}
}

// tmuxNotEnded reports a tmux session whose end was asked for but not
// confirmed (Python: TMUX_SESSION_NOT_ENDED), in the log and, when wired,
// in the security audit log.
func (m *Manager) tmuxNotEnded(kv ...any) {
	m.log.Warn("tmux session not ended", append([]any{"event", "TMUX_SESSION_NOT_ENDED"}, kv...)...)
	if m.audit != nil {
		m.audit.SecurityWarning("TMUX_SESSION_NOT_ENDED", kv...)
	}
}
