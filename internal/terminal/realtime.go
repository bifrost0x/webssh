package terminal

import (
	"context"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
)

// openMaxPayload fits a typed password and every field of the target.
const openMaxPayload = 8 << 10

// Routes are the terminal and prompt message types for the realtime
// endpoint. Handlers that wait on the network are Async; the others run on
// the read loop and take only short locks.
func (m *Manager) Routes() []protocol.Route {
	return []protocol.Route{
		protocol.Handle(protocol.TypeTerminalOpen,
			protocol.Spec{Async: true, Mutates: true, RateKey: "ssh_connect", Timeout: m.cfg.OpenTimeout, MaxPayload: openMaxPayload},
			m.open),
		protocol.Handle(protocol.TypeTerminalCancel, protocol.Spec{}, m.cancelOpen),
		protocol.Handle(protocol.TypeTerminalDiscardLate, protocol.Spec{Mutates: true}, m.discardLate),
		protocol.Handle(protocol.TypeTerminalAttach, protocol.Spec{}, m.attachRequest),
		protocol.Handle(protocol.TypeTerminalDetach, protocol.Spec{}, m.detachRequest),
		protocol.Handle(protocol.TypeTerminalClose, protocol.Spec{Mutates: true}, m.closeRequest),
		protocol.Handle(protocol.TypeTerminalResize, protocol.Spec{}, m.resizeRequest),
		protocol.Handle(protocol.TypeTerminalRename, protocol.Spec{Mutates: true}, m.renameRequest),
		protocol.Handle(protocol.TypePromptAnswer, protocol.Spec{}, m.answerRequest),
	}
}

func (m *Manager) attachRequest(ctx context.Context, peer protocol.Peer, req protocol.TerminalAttach) (protocol.TerminalAttached, error) {
	p, err := principal.Require(ctx)
	if err != nil {
		return protocol.TerminalAttached{}, err
	}
	s, err := m.lookup(p.UserID, req.SessionID)
	if err != nil {
		return protocol.TerminalAttached{}, err
	}
	return m.attach(peer, s, req.Ch, req.AfterSeq, false)
}

// detachRequest unbinds a channel; an unknown channel is a no-op (also
// after terminal.resync_required).
func (m *Manager) detachRequest(ctx context.Context, peer protocol.Peer, req protocol.ChannelRef) (*protocol.Empty, error) {
	if _, err := principal.Require(ctx); err != nil {
		return nil, err
	}
	if a := m.attachmentOf(peer, req.Ch); a != nil && a.sess != nil {
		m.detach(a, "")
	}
	return nil, nil
}

// closeRequest ends a session; every connection it was attached to and the
// requester receive terminal.closed.
func (m *Manager) closeRequest(ctx context.Context, peer protocol.Peer, req protocol.SessionRef) (*protocol.Empty, error) {
	p, err := principal.Require(ctx)
	if err != nil {
		return nil, err
	}
	s, err := m.lookup(p.UserID, req.SessionID)
	if err != nil {
		return nil, err
	}
	s.terminate(reasonUser, peer)
	return nil, nil
}

// discardLate ends a session whose connection attempt the page had given
// up on.
func (m *Manager) discardLate(ctx context.Context, peer protocol.Peer, req protocol.SessionRef) (*protocol.Empty, error) {
	p, err := principal.Require(ctx)
	if err != nil {
		return nil, err
	}
	s, err := m.lookup(p.UserID, req.SessionID)
	if err != nil {
		return nil, err
	}
	s.terminate(reasonDiscarded, peer)
	return nil, nil
}

func (m *Manager) resizeRequest(ctx context.Context, peer protocol.Peer, req protocol.TerminalResize) (*protocol.Empty, error) {
	if _, err := principal.Require(ctx); err != nil {
		return nil, err
	}
	a := m.attachmentOf(peer, req.Ch)
	if a == nil || a.sess == nil {
		return nil, fault.New(fault.NotFound, "Session not found.")
	}
	a.sess.resize(req.Rows, req.Cols)
	return nil, nil
}

// renameRequest sets the display name; an empty name clears it. It lives
// with the session and is listed again after a reload.
func (m *Manager) renameRequest(ctx context.Context, _ protocol.Peer, req protocol.TerminalRename) (*protocol.Empty, error) {
	p, err := principal.Require(ctx)
	if err != nil {
		return nil, err
	}
	s, err := m.lookup(p.UserID, req.SessionID)
	if err != nil {
		return nil, err
	}
	s.rename(displayName(req.Name))
	return nil, nil
}

func (m *Manager) answerRequest(ctx context.Context, peer protocol.Peer, req protocol.PromptAnswer) (*protocol.Empty, error) {
	p, err := principal.Require(ctx)
	if err != nil {
		return nil, err
	}
	return nil, m.prompts.resolve(peer.ID(), p.UserID, req.PromptID, req.Kind, req.Accepted)
}
