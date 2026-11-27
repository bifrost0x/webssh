package hostops

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"regexp"
	"sync"
	"time"
)

// Limits of prepared operations (app/server_operations.py).
const (
	intentTTL        = 90 * time.Second
	maxIntents       = 256
	maxIntentsOfUser = 16
)

var intentToken = regexp.MustCompile(`^[A-Za-z0-9_-]{20,128}$`)

// intent is one reviewed write, bound to the user, the sign-in, the
// session and its connection. Only the SHA-256 of its token is kept.
type intent struct {
	userID       int64
	authID       string
	sessionID    string
	done         <-chan struct{}
	action       string
	cmd          opCommand
	host         string
	username     string
	expires      time.Time
	confirmation string // the host to type for system.reboot
}

type intents struct {
	mu    sync.Mutex
	items map[string]intent
}

func intentDigest(token string) (string, error) {
	if !intentToken.MatchString(token) {
		return "", opErr("invalid_intent")
	}
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:]), nil
}

// add stores in and returns its token (secrets.token_urlsafe(32)).
func (s *intents) add(in intent, now time.Time) (string, error) {
	var raw [32]byte
	_, _ = rand.Read(raw[:])
	token := base64.RawURLEncoding.EncodeToString(raw[:])
	key, err := intentDigest(token)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	mine := 0
	for k, v := range s.items {
		switch {
		case !now.Before(v.expires):
			delete(s.items, k)
		case v.userID == in.userID:
			mine++
		}
	}
	if len(s.items) >= maxIntents || mine >= maxIntentsOfUser {
		return "", opErr("busy")
	}
	if s.items == nil {
		s.items = map[string]intent{}
	}
	s.items[key] = in
	return token, nil
}

// get is get_intent: the unexpired intent of the user and sign-in, taken
// out when consume is set. The caller checks the session afterwards.
func (s *intents) get(token string, userID int64, authID string, now time.Time, consume bool) (intent, error) {
	key, err := intentDigest(token)
	if err != nil {
		return intent{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	in, ok := s.items[key]
	if !ok || in.userID != userID || in.authID != authID || !now.Before(in.expires) {
		return intent{}, opErr("invalid_intent")
	}
	if consume {
		delete(s.items, key)
	}
	return in, nil
}
