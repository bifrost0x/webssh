package files

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	json "encoding/json/v2"
	"net/http"
	"sync"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
)

// Large answers of the editor and the image preview do not travel through
// the realtime connection, whose outbound queue stays bounded per
// connection (8 MiB): the answer is parked here and the page fetches it
// once over HTTP (GET /api/files/handoff/{token}). Parked answers are
// bounded per user and in total and expire unless fetched.
const (
	// DefaultHandoffInline is the largest answer sent inline.
	DefaultHandoffInline = 1 << 20
	// DefaultHandoffBudget bounds the bytes parked for all users.
	DefaultHandoffBudget = 128 << 20
	handoffTTL           = 60 * time.Second
	handoffsPerUser      = 4
)

// HandoffPath is the route that hands a parked answer out.
const HandoffPath = "GET /api/files/handoff/{token}"

type handoff struct {
	user    int64
	session string
	body    []byte
	expires time.Time
	timer   *time.Timer
}

type handoffs struct {
	inline, budget int64
	mu             sync.Mutex
	items          map[[32]byte]*handoff // by SHA-256 of the token
	used           int64
}

func newHandoffs(inline, budget int64) *handoffs {
	return &handoffs{inline: inline, budget: budget, items: map[[32]byte]*handoff{}}
}

var errHandoffBusy = fault.New(fault.Busy, "Too many large files are being opened. Try again shortly.")

// park keeps body for c's browser session and returns its token. The
// oldest parked answer of the user gives way beyond the per-user bound; a
// full budget refuses with busy.
func (h *handoffs) park(c Caller, body []byte, now time.Time) (string, error) {
	var raw [32]byte
	_, _ = rand.Read(raw[:]) // never fails (crypto/rand)
	token := base64.RawURLEncoding.EncodeToString(raw[:])
	key := sha256.Sum256([]byte(token))
	h.mu.Lock()
	defer h.mu.Unlock()
	var mine []*handoff
	var oldest [32]byte
	for k, it := range h.items {
		if it.user == c.P.UserID {
			mine = append(mine, it)
			if len(mine) == 1 || it.expires.Before(h.items[oldest].expires) {
				oldest = k
			}
		}
	}
	if len(mine) >= handoffsPerUser {
		h.dropLocked(oldest)
	}
	if h.used+int64(len(body)) > h.budget {
		return "", errHandoffBusy
	}
	it := &handoff{user: c.P.UserID, session: c.P.SessionID, body: body, expires: now.Add(handoffTTL)}
	it.timer = time.AfterFunc(handoffTTL, func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		if h.items[key] == it {
			h.dropLocked(key)
		}
	})
	h.items[key] = it
	h.used += int64(len(body))
	return token, nil
}

func (h *handoffs) dropLocked(key [32]byte) {
	if it, ok := h.items[key]; ok {
		it.timer.Stop()
		h.used -= int64(len(it.body))
		delete(h.items, key)
	}
}

// take hands the answer out once, only to the browser session it was
// parked for.
func (h *handoffs) take(p principal.Principal, token string) ([]byte, bool) {
	key := sha256.Sum256([]byte(token))
	h.mu.Lock()
	defer h.mu.Unlock()
	it, ok := h.items[key]
	if !ok || it.user != p.UserID || it.session != p.SessionID {
		return nil, false
	}
	h.dropLocked(key)
	return it.body, true
}

// revoke drops what was parked for a revoked session or user.
func (h *handoffs) revoke(rev principal.Revocation) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for k, it := range h.items {
		if it.user == rev.UserID && (rev.SessionID == "" || it.session == rev.SessionID) {
			h.dropLocked(k)
		}
	}
}

// offload returns v itself when its JSON is small, else the answer with
// only the correlation members and the handoff token (withToken).
func offload[T any](s *Service, c Caller, v *T, withToken func(token string) *T) (*T, error) {
	body, err := json.Marshal(v)
	if err != nil {
		return nil, fault.Wrap(fault.Internal, err, "")
	}
	if int64(len(body)) <= s.handoff.inline {
		return v, nil
	}
	token, err := s.handoff.park(c, body, s.opts.Now())
	if err != nil {
		return nil, err
	}
	return withToken(token), nil
}

// HandoffHTTP serves the parked answers (HandoffPath, a user route).
func (s *Service) HandoffHTTP(w http.ResponseWriter, r *http.Request) {
	p, err := principal.Require(r.Context())
	body, ok := []byte(nil), false
	if err == nil {
		body, ok = s.handoff.take(p, r.PathValue("token"))
	}
	w.Header().Set("Cache-Control", "no-store")
	if !ok {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"success":false,"code":"SOURCE_UNAVAILABLE","error":"The file is no longer available. Open it again."}`))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}

// Revoke drops the parked answers of a revoked session (K6).
func (s *Service) Revoke(rev principal.Revocation) { s.handoff.revoke(rev) }
