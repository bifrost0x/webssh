package terminal

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
	"github.com/bifrost0x/webssh/internal/ssh/client"
)

// prompt is one question to the user during a connection attempt. It is
// bound to the connection, the user and the attempt's request_id; only
// that connection can answer it.
type prompt struct {
	id        string
	kind      string
	peer      uint64
	owner     int64
	requestID string
	answer    chan bool // capacity 1, written once
	answered  bool
}

// prompts is the process-wide registry of pending prompts.
type prompts struct {
	max     int
	mu      sync.Mutex
	pending map[string]*prompt
}

func newPrompts(limit int) *prompts {
	return &prompts{max: limit, pending: map[string]*prompt{}}
}

// newPromptID returns 32 URL-safe characters (Python: token_urlsafe(24)).
func newPromptID() string {
	var b [24]byte
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}

func (r *prompts) add(q *prompt) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.pending) >= r.max {
		return false
	}
	r.pending[q.id] = q
	return true
}

func (r *prompts) remove(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.pending, id)
}

// resolve delivers the user's answer to a prompt of this connection and
// user. Every mismatch looks like a missing prompt.
func (r *prompts) resolve(peer uint64, owner int64, id, kind string, accepted bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	q := r.pending[id]
	if q == nil || q.peer != peer || q.owner != owner || q.kind != kind || q.answered {
		return fault.New(fault.NotFound, "The prompt is no longer open.")
	}
	q.answered = true
	q.answer <- accepted
	return nil
}

// closePeer declines every prompt of an ended connection.
func (r *prompts) closePeer(peer uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, q := range r.pending {
		if q.peer == peer && !q.answered {
			q.answered = true
			q.answer <- false
		}
	}
}

// interaction implements client.Interaction for one connection attempt.
type interaction struct {
	m         *Manager
	peer      protocol.Peer
	owner     int64
	requestID string
}

var _ client.Interaction = (*interaction)(nil)

// HostKey asks whether to trust a host key seen for the first time.
func (ix *interaction) HostKey(ctx context.Context, q client.HostKeyPrompt) (bool, error) {
	return ix.ask(ctx, protocol.PromptKindHostKey, func(id string) (string, any) {
		return protocol.TypePromptHostKey, protocol.PromptHostKey{
			PromptID: id, RequestID: ix.requestID, Context: string(q.Role),
			Host: q.Host, Port: q.Port, KeyType: q.KeyType, Fingerprint: q.Fingerprint,
		}
	})
}

// Banner asks whether to accept the pre-authentication banner. The dialer
// has bounded and sanitized the text.
func (ix *interaction) Banner(ctx context.Context, q client.BannerPrompt) (bool, error) {
	return ix.ask(ctx, protocol.PromptKindBanner, func(id string) (string, any) {
		return protocol.TypePromptBanner, protocol.PromptBanner{
			PromptID: id, RequestID: ix.requestID, Context: string(q.Role),
			Host: q.Host, Port: q.Port, Banner: q.Banner,
		}
	})
}

// ask sends the prompt and waits for the answer, the attempt's end or the
// prompt timeout, which declines it. prompt.closed withdraws it in every
// case. A full registry declines at once, as the Python release did.
func (ix *interaction) ask(ctx context.Context, kind string, event func(id string) (string, any)) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	q := &prompt{id: newPromptID(), kind: kind, peer: ix.peer.ID(), owner: ix.owner, requestID: ix.requestID, answer: make(chan bool, 1)}
	if !ix.m.prompts.add(q) {
		ix.m.log.Warn("terminal prompt refused: too many pending prompts")
		return false, nil
	}
	defer func() {
		ix.m.prompts.remove(q.id)
		_ = ix.peer.SendEvent(protocol.TypePromptClosed, protocol.PromptClosed{PromptID: q.id, RequestID: ix.requestID})
	}()
	typ, payload := event(q.id)
	if err := ix.peer.SendEvent(typ, payload); err != nil {
		return false, errPeerGone
	}
	timer := time.NewTimer(ix.m.cfg.PromptTimeout)
	defer timer.Stop()
	select {
	case ok := <-q.answer:
		return ok && ctx.Err() == nil, nil
	case <-ctx.Done():
		return false, ctx.Err()
	case <-timer.C:
		return false, nil
	}
}
