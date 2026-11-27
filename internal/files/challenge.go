package files

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"regexp"
	"slices"
	"sync"
	"time"
)

// Bounds of the save challenges (app/socket_file_control.py).
const (
	challengeTTL     = 120 * time.Second
	challengesTotal  = 256
	challengesByUser = 4
)

var challengePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{32,64}$`)

// saveFingerprint is the exact save a challenge allows once more: same
// connection, source, path, encoding, newline mode, revision and body.
type saveFingerprint struct {
	owner                             owner
	sourceID, path, encoding, newline string
	revision                          string
	size                              int
	digest                            [sha256.Size]byte
}

func fingerprint(o owner, req SaveRequest) saveFingerprint {
	return saveFingerprint{
		owner: o, sourceID: req.SourceID, path: req.Path, encoding: req.Encoding, newline: req.Newline,
		revision: req.ExpectedRevision, size: len(req.Content), digest: sha256.Sum256([]byte(req.Content)),
	}
}

type challenge struct {
	fp      saveFingerprint
	expires time.Time
	issued  time.Time
}

// challenges are the tokens of the SMB save challenge: a save refused with
// SMB_RECOVERABLE_REPLACE_REQUIRED gets a token, and the same save sent
// again with strategy recoverable_swap and that token is not charged to
// the editor budget a second time.
type challenges struct {
	now func() time.Time

	mu     sync.Mutex
	tokens map[string]challenge
}

func newChallenges(now func() time.Time) *challenges {
	return &challenges{now: now, tokens: map[string]challenge{}}
}

func (c *challenges) pruneLocked(now time.Time) {
	for t, ch := range c.tokens {
		if !now.Before(ch.expires) {
			delete(c.tokens, t)
		}
	}
}

// issue returns a new token for the save fp, evicting the oldest tokens of
// the user and in total beyond the bounds.
func (c *challenges) issue(fp saveFingerprint) string {
	var b [32]byte
	_, _ = rand.Read(b[:]) // never fails (crypto/rand)
	token := base64.RawURLEncoding.EncodeToString(b[:])
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pruneLocked(now)
	evict := func(match func(challenge) bool, limit int) {
		var mine []string
		for t, ch := range c.tokens {
			if match(ch) {
				mine = append(mine, t)
			}
		}
		slices.SortFunc(mine, func(a, b string) int { return c.tokens[a].issued.Compare(c.tokens[b].issued) })
		for len(mine) >= limit {
			delete(c.tokens, mine[0])
			mine = mine[1:]
		}
	}
	evict(func(ch challenge) bool { return ch.fp.owner.user == fp.owner.user }, challengesByUser)
	evict(func(challenge) bool { return true }, challengesTotal)
	c.tokens[token] = challenge{fp: fp, issued: now, expires: now.Add(challengeTTL)}
	return token
}

// consume claims token once; it reports whether it was issued for exactly
// the save fp.
func (c *challenges) consume(token string, fp saveFingerprint) bool {
	if !challengePattern.MatchString(token) {
		return false
	}
	now := c.now()
	c.mu.Lock()
	ch, ok := c.tokens[token]
	delete(c.tokens, token)
	c.mu.Unlock()
	return ok && now.Before(ch.expires) && ch.fp == fp
}
