package session

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"regexp"
	"slices"
	"time"

	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/store"
)

// Assurance is the strength of a sign-in (auth_assurance.AssuranceLevel).
type Assurance string

// Assurance levels, weakest first.
const (
	Basic             Assurance = "BASIC"
	MFA               Assurance = "MFA"
	PhishingResistant Assurance = "PHISHING_RESISTANT"
)

// Rank orders the levels; unknown levels rank below Basic.
func (a Assurance) Rank() int {
	return slices.Index([]Assurance{Basic, MFA, PhishingResistant}, a)
}

// Lifetimes of the Python release: the account setting
// authentication_session_duration_minutes (30 min to 8 h, default 30 min)
// and REMEMBER_COOKIE_DURATION (7 days) for "stay signed in".
const (
	DefaultMinutes   = 30
	RememberLifetime = 7 * 24 * time.Hour
)

// AllowedMinutes are the values of the account setting.
var AllowedMinutes = []int{30, 60, 120, 240, 480}

// MethodRecovery marks a session opened with a recovery code; it may only
// repair second factors until the restriction is cleared.
const MethodRecovery = "recovery_code"

const maxMethods = 8

var methodPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,23}$`)

// Session is one browser sign-in.
type Session struct {
	ID              string
	UserID          int64
	AuthGeneration  int64
	PrimaryMethod   string
	Methods         []string
	Assurance       Assurance
	Remember        bool
	AuthenticatedAt time.Time
	// StrongAt is when a second factor or passkey was last verified; zero
	// for a password-only sign-in.
	StrongAt  time.Time
	ExpiresAt time.Time
	epoch     string
}

// Recovery reports whether the session still needs factor repair.
func (s Session) Recovery() bool { return slices.Contains(s.Methods, MethodRecovery) }

// Standing is what the session package needs to know about an account
// (provided by internal/accounts).
type Standing struct {
	Exists     bool
	Username   string
	IsAdmin    bool
	Locked     bool
	Managed    bool // LDAP or GitHub provisioned
	Generation int64
}

// eligible is the account check of load_user and finalize_login: the
// account exists, is not locked and is not a directory-managed admin.
func (s Standing) eligible() bool { return s.Exists && !s.Locked && !(s.IsAdmin && s.Managed) }

// Accounts reads an account's standing (provided by internal/accounts).
// A missing account is Standing{Exists: false} and no error.
type Accounts interface {
	Standing(ctx context.Context, userID int64) (Standing, error)
}

// Durations reads the account setting for the session lifetime in
// minutes (provided by internal/settings). Values outside AllowedMinutes
// and errors use DefaultMinutes.
type Durations interface {
	SessionMinutes(ctx context.Context, userID int64) (int, error)
}

// MAC is the part of the keyring the package uses.
type MAC interface {
	MAC(p keyring.Purpose, msg []byte) []byte
}

// Schema is the session store.
func Schema() store.Schema {
	return store.Schema{Owner: "session", Migrations: []store.Migration{{Version: 1, SQL: `
CREATE TABLE session_sessions (
	id                  TEXT PRIMARY KEY,
	token_mac           BLOB NOT NULL UNIQUE,
	user_id             INTEGER NOT NULL,
	auth_generation     INTEGER NOT NULL,
	epoch               TEXT NOT NULL,
	primary_method      TEXT NOT NULL,
	methods             TEXT NOT NULL,
	assurance           TEXT NOT NULL CHECK (assurance IN ('BASIC', 'MFA', 'PHISHING_RESISTANT')),
	remember            INTEGER NOT NULL CHECK (remember IN (0, 1)),
	authenticated_us    INTEGER NOT NULL,
	strong_us           INTEGER,
	expires_us          INTEGER NOT NULL
) STRICT;
CREATE INDEX session_sessions_user ON session_sessions (user_id);
CREATE INDEX session_sessions_expiry ON session_sessions (expires_us);
CREATE TABLE session_epoch (
	singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
	value     TEXT NOT NULL
) STRICT;
INSERT INTO session_epoch (singleton, value) VALUES (1, lower(hex(randomblob(32))));`}, {Version: 2, SQL: `
CREATE TABLE session_revocations (
	seq        INTEGER PRIMARY KEY,
	session_id TEXT NOT NULL,
	user_id    INTEGER NOT NULL,
	reason     TEXT NOT NULL,
	origin     TEXT NOT NULL,
	at_us      INTEGER NOT NULL
) STRICT;
CREATE INDEX session_revocations_at ON session_revocations (at_us);`}}}
}

func randomText(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b) // crypto/rand.Read never fails (Go 1.24+)
	return base64.RawURLEncoding.EncodeToString(b)
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// maxTokenLen bounds token input before it is MACed.
const maxTokenLen = 128

func tokenMAC(m MAC, token string) []byte {
	return m.MAC(keyring.SessionToken, []byte("webssh-session-v1\x00"+token))
}

// Handle is the stable, management-only reference of a session in the
// session list (64 hex digits, as in the Python release). It is derived
// from the session ID and never usable as a credential.
func Handle(m MAC, id string) string {
	return hex.EncodeToString(m.MAC(keyring.SessionToken, []byte("webssh-session-inventory-v1\x00"+id)))
}

// pyISO renders t like Python's naive datetime.isoformat() in UTC:
// microseconds only when they are not zero.
func pyISO(t time.Time) string {
	t = t.UTC()
	if t.Nanosecond()/1000 == 0 {
		return t.Format("2006-01-02T15:04:05")
	}
	return t.Format("2006-01-02T15:04:05.000000")
}
