package vault

import (
	"cmp"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"slices"
	"sync"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
)

// Bounds of the intents (INTENTS_PER_USER, INTENTS_GLOBAL).
const (
	IntentsPerUser = 8
	IntentsTotal   = 4096
)

type intentKind int

const (
	intentNative intentKind = iota + 1 // a prepared mutation of the page
	intentTarget                       // an authorized one-off target
)

// intent is a prepared credential operation bound to the user, the
// browser session and the credentials policy revision.
type intent struct {
	kind    intentKind
	userID  int64
	session string
	expires time.Time
	policy  string
	seq     uint64 // order of creation, for intents of the same instant

	// native
	digest      string
	frozen      string // fingerprint of the resource the mutation assigns
	prior       *Assignment
	assignsTo   string // resource id, "" for other mutations
	hasResource bool

	// target
	target       string // normalized target
	credentialID string
	version      string
	route        string // fingerprint of the live route, "" without one
}

type assurance struct {
	expires time.Time
	policy  string
}

// intents holds the prepared operations and the binding assurance of
// recent step-ups. Both live only in memory, as in the Python release:
// a restart asks the user to start again.
type intents struct {
	mu        sync.Mutex
	now       func() time.Time
	byKey     map[string]intent
	assurance map[sessionKey]assurance
	attempts  map[attemptKey][]time.Time
	seq       uint64
}

type sessionKey struct {
	userID  int64
	session string
}

type attemptKey struct {
	userID int64
	bucket string
}

func newIntents(now func() time.Time) *intents {
	return &intents{now: now, byKey: map[string]intent{}, assurance: map[sessionKey]assurance{}, attempts: map[attemptKey][]time.Time{}}
}

func tokenKey(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// remember stores in and returns its token. A user at the per-user bound
// replaces their own oldest intent; the global bound is busy.
func (s *intents) remember(p principal.Principal, policy string, in intent) (string, error) {
	b := make([]byte, 32)
	_, _ = rand.Read(b) // crypto/rand.Read never fails
	token := base64.RawURLEncoding.EncodeToString(b)
	now := s.now()
	in.userID, in.session, in.policy, in.expires = p.UserID, p.SessionID, policy, now.Add(IntentTTL)
	s.mu.Lock()
	defer s.mu.Unlock()
	type owned struct {
		key     string
		expires time.Time
		seq     uint64
	}
	var own []owned
	for k, v := range s.byKey {
		switch {
		case !v.expires.After(now):
			delete(s.byKey, k)
		case v.userID == p.UserID:
			own = append(own, owned{k, v.expires, v.seq})
		}
	}
	slices.SortFunc(own, func(a, b owned) int {
		if c := a.expires.Compare(b.expires); c != 0 {
			return c
		}
		return cmp.Compare(a.seq, b.seq)
	})
	for len(own) >= IntentsPerUser {
		delete(s.byKey, own[0].key)
		own = own[1:]
	}
	if len(s.byKey) >= IntentsTotal {
		return "", fault.New(fault.Busy, "")
	}
	s.seq++
	in.seq = s.seq
	s.byKey[tokenKey(token)] = in
	return token, nil
}

// lookup returns the intent of token for p; consume removes it. Another
// user's, another session's, an expired or a foreign-policy intent is
// invalid_intent.
func (s *intents) lookup(p principal.Principal, policy, token string, consume bool) (intent, error) {
	if len(token) < 30 || len(token) > 128 {
		return intent{}, fault.New(fault.InvalidIntent, "")
	}
	key := tokenKey(token)
	s.mu.Lock()
	defer s.mu.Unlock()
	in, ok := s.byKey[key]
	if !ok || in.userID != p.UserID || in.session != p.SessionID || !in.expires.After(s.now()) || in.policy != policy {
		return intent{}, fault.New(fault.InvalidIntent, "")
	}
	if consume {
		delete(s.byKey, key)
	}
	return in, nil
}

// assured reports whether this session consumed a credentials.vault grant
// within BindingAssurance under the current policy.
func (s *intents) assured(p principal.Principal, policy string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := sessionKey{p.UserID, p.SessionID}
	a, ok := s.assurance[k]
	if ok && !a.expires.After(s.now()) {
		delete(s.assurance, k)
		return false
	}
	return ok && a.policy == policy
}

func (s *intents) assure(p principal.Principal, policy string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for k, a := range s.assurance {
		if !a.expires.After(now) {
			delete(s.assurance, k)
		}
	}
	s.assurance[sessionKey{p.UserID, p.SessionID}] = assurance{expires: now.Add(BindingAssurance), policy: policy}
}

// allow counts one attempt of a bucket and reports whether it is within
// limit per minute (check_reauth_rate_limit of the Python release).
func (s *intents) allow(userID int64, bucket string, limit int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	k := attemptKey{userID, bucket}
	recent := slices.DeleteFunc(s.attempts[k], func(t time.Time) bool { return now.Sub(t) >= time.Minute })
	if len(recent) >= limit {
		s.attempts[k] = recent
		return false
	}
	s.attempts[k] = append(recent, now)
	return true
}

// revokeUser drops a user's intents and assurance, as revoke() does after
// a password change or a lock.
func (s *intents) revokeUser(userID int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.byKey {
		if v.userID == userID {
			delete(s.byKey, k)
		}
	}
	for k := range s.assurance {
		if k.userID == userID {
			delete(s.assurance, k)
		}
	}
}

// sweep drops expired entries; it runs periodically.
func (s *intents) sweep() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for k, v := range s.byKey {
		if !v.expires.After(now) {
			delete(s.byKey, k)
		}
	}
	for k, a := range s.assurance {
		if !a.expires.After(now) {
			delete(s.assurance, k)
		}
	}
	for k, ts := range s.attempts {
		if len(ts) == 0 || now.Sub(ts[len(ts)-1]) >= time.Minute {
			delete(s.attempts, k)
		}
	}
}
