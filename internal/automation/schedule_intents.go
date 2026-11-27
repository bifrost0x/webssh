package automation

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/jsontext"
	"slices"
	"sync"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
)

// Bounds of the schedule intents (remember_intent of
// app/automation_store.py).
const (
	IntentTTL       = 300 * time.Second
	minIntentLength = 30
	maxIntentLength = 128
)

// scheduleIntent is a reviewed schedule waiting for the user's approval.
type scheduleIntent struct {
	Snapshot   Snapshot
	Cron, Zone string
	ScheduleID string // empty for a new schedule
	Revision   int64  // of ScheduleID when the review started
	Account    jsontext.Value
	Policy     string
	Binding    jsontext.Value
}

type intentEntry struct {
	userID  int64
	session string
	expires time.Time
	value   scheduleIntent
}

// scheduleIntents keeps the intents in memory, keyed by the SHA-256 of
// their token. An intent belongs to the user and the browser session that
// prepared it. A user at the per-user bound replaces their oldest intent;
// the global bound answers busy.
type scheduleIntents struct {
	now func() time.Time
	mu  sync.Mutex
	m   map[string]intentEntry
}

func newScheduleIntents(now func() time.Time) *scheduleIntents {
	return &scheduleIntents{now: now, m: map[string]intentEntry{}}
}

func intentKey(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func (in *scheduleIntents) remember(p principal.Principal, v scheduleIntent) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	in.mu.Lock()
	defer in.mu.Unlock()
	now := in.now()
	in.sweepLocked(now)
	var own []string
	for k, e := range in.m {
		if e.userID == p.UserID {
			own = append(own, k)
		}
	}
	slices.SortFunc(own, func(a, b string) int { return in.m[a].expires.Compare(in.m[b].expires) })
	for len(own) >= intentsPerUser {
		delete(in.m, own[0])
		own = own[1:]
	}
	if len(in.m) >= intentsGlobal {
		return "", fault.New(fault.Busy, "")
	}
	in.m[intentKey(token)] = intentEntry{userID: p.UserID, session: p.SessionID, expires: now.Add(IntentTTL), value: v}
	return token, nil
}

// get returns the intent of token for p; consume removes it.
func (in *scheduleIntents) get(p principal.Principal, token string, consume bool) (scheduleIntent, error) {
	invalid := fault.New(fault.InvalidIntent, "")
	if len(token) < minIntentLength || len(token) > maxIntentLength {
		return scheduleIntent{}, invalid
	}
	key := intentKey(token)
	in.mu.Lock()
	defer in.mu.Unlock()
	e, ok := in.m[key]
	if !ok || e.userID != p.UserID || e.session != p.SessionID || !in.now().Before(e.expires) {
		return scheduleIntent{}, invalid
	}
	if consume {
		delete(in.m, key)
	}
	return e.value, nil
}

func (in *scheduleIntents) sweepLocked(now time.Time) {
	for k, e := range in.m {
		if !now.Before(e.expires) {
			delete(in.m, k)
		}
	}
}

// revoke drops the intents of an ended session, or of every session of the
// account for an account-wide revocation.
func (in *scheduleIntents) revoke(rev principal.Revocation) {
	in.mu.Lock()
	defer in.mu.Unlock()
	for k, e := range in.m {
		if e.userID == rev.UserID && (rev.SessionID == "" || e.session == rev.SessionID) {
			delete(in.m, k)
		}
	}
}

func (in *scheduleIntents) sweep() {
	in.mu.Lock()
	defer in.mu.Unlock()
	in.sweepLocked(in.now())
}
