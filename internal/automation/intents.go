package automation

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"slices"
	"strconv"
	"sync"
	"time"
)

// Bounds of the review intents (automation_store.py).
const (
	intentsPerUser = 8
	intentsGlobal  = 4096
	intentLifetime = 300 * time.Second
)

// review is a reviewed run, frozen until the start: runbook, targets,
// the digests of their keys and the bindings of their saved passwords.
type review struct {
	userID     int64
	sessionID  string
	book       Runbook
	targets    []Frozen
	keyDigests map[string]string
	bindings   map[string]string
	// check is the validation of the schedule a manual run was prepared
	// from (run now), nil for a plain review.
	check   func(context.Context) error
	expires time.Time
}

func (r *review) confirmation() string { return strconv.Itoa(len(r.targets)) }

// intents holds the reviews by the digest of their token.
type intents struct {
	mu   sync.Mutex
	byID map[string]*review
}

func tokenKey(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// remember is remember_intent: a user at the per-user bound replaces
// their own oldest review, so one account can neither lock itself out
// nor, with a few others, fill the shared table; the global bound only
// limits memory.
func (in *intents) remember(r *review, now time.Time) (string, error) {
	var raw [32]byte
	_, _ = rand.Read(raw[:])
	token := base64.RawURLEncoding.EncodeToString(raw[:])
	r.expires = now.Add(intentLifetime)
	in.mu.Lock()
	defer in.mu.Unlock()
	if in.byID == nil {
		in.byID = map[string]*review{}
	}
	type owned struct {
		key     string
		expires time.Time
	}
	var own []owned
	for k, v := range in.byID {
		switch {
		case !v.expires.After(now):
			delete(in.byID, k)
		case v.userID == r.userID:
			own = append(own, owned{k, v.expires})
		}
	}
	slices.SortFunc(own, func(a, b owned) int { return a.expires.Compare(b.expires) })
	for len(own) >= intentsPerUser {
		delete(in.byID, own[0].key)
		own = own[1:]
	}
	if len(in.byID) >= intentsGlobal {
		return "", Fail("busy")
	}
	in.byID[tokenKey(token)] = r
	return token, nil
}

// get returns the review of the token for the user and session; consume
// removes it.
func (in *intents) get(token string, userID int64, sessionID string, now time.Time, consume bool) (*review, error) {
	if len(token) < 30 || len(token) > 128 {
		return nil, Fail("invalid_intent")
	}
	key := tokenKey(token)
	in.mu.Lock()
	defer in.mu.Unlock()
	r, ok := in.byID[key]
	if !ok || r.userID != userID || r.sessionID != sessionID || !r.expires.After(now) {
		return nil, Fail("invalid_intent")
	}
	if consume {
		delete(in.byID, key)
	}
	return r, nil
}

// drop removes the reviews that match.
func (in *intents) drop(match func(*review) bool) {
	in.mu.Lock()
	defer in.mu.Unlock()
	for k, v := range in.byID {
		if match(v) {
			delete(in.byID, k)
		}
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }
