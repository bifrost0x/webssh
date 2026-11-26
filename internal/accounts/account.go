package accounts

import (
	"context"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/bifrost0x/webssh/internal/store"
)

// Manager names who provisions an account besides WebSSH itself.
type Manager string

// Account managers. An LDAP- or GitHub-managed account never signs in
// with a local password.
const (
	ManagedLocal  Manager = ""
	ManagedLDAP   Manager = "ldap"
	ManagedGitHub Manager = "github"
)

// Account is one user.
type Account struct {
	ID       int64
	Username string
	// Incarnation identifies this account among accounts that held the
	// same id (migration specification 4.2); it never changes.
	Incarnation string
	// HistoryGeneration is the input of the browser history namespace.
	HistoryGeneration string
	CreatedAt         time.Time // zero for legacy accounts without a value
	LastLogin         time.Time
	IsAdmin           bool
	IsLocked          bool
	AuthGeneration    int64
	MFARequired       bool
	Managed           Manager
}

// Credentials creates local passwords (provided by internal/auth/local).
type Credentials interface {
	ValidateNew(password string) string
	Hash(ctx context.Context, password string) (string, error)
	StoreTx(ctx context.Context, tx *store.Tx, userID int64, hash string) error
}

// Auditor writes security events (provided by internal/audit).
type Auditor interface {
	Security(event string, kv ...any)
}

// Username rules for new accounts (validate_new_user). Existing accounts
// keep their names, including Unicode ones from older releases.
const (
	minNameRunes = 3
	maxNameRunes = 32
)

var newNamePattern = regexp.MustCompile(`^[A-Za-z0-9_]+$`)

// fullFolds are the characters whose Unicode case folding is not a single
// lower-case letter and folds to ASCII; only those can make an existing
// legacy name collide with a new ASCII name.
var fullFolds = map[rune]string{
	'ß': "ss", 'ẞ': "ss", 'ſ': "s", 'ﬀ': "ff", 'ﬁ': "fi", 'ﬂ': "fl", 'ﬃ': "ffi", 'ﬄ': "ffl", 'ﬅ': "st", 'ﬆ': "st",
}

// FoldName approximates Python's str.casefold() for comparing account
// names: simple lower-casing plus the full foldings that reach ASCII.
func FoldName(s string) string {
	var b strings.Builder
	for _, r := range s {
		if f, ok := fullFolds[r]; ok {
			b.WriteString(f)
			continue
		}
		b.WriteRune(unicode.ToLower(r))
	}
	return b.String()
}

// validateNewName returns the Python message for an invalid new name, or "".
func validateNewName(name string) string {
	if n := utf8.RuneCountInString(name); n < minNameRunes || n > maxNameRunes {
		return "Username must be between 3 and 32 characters"
	}
	if !newNamePattern.MatchString(name) {
		return "Username can only contain letters, numbers, and underscores"
	}
	return ""
}

// Admins is the ADMIN_USERS list. It follows variant B (decision K-11):
// the configuration keeps the last word and that is visible. Listed
// accounts are marked as managed by the configuration, demoting them is
// refused with an explanation, a listed name without an account cannot be
// registered (only an administrator may create it), and converting a
// listed LDAP or GitHub account into a local one is refused with 409.
type Admins []string

// Reserves reports whether the list names this account name, ignoring
// case (is_config_admin_name): such a name may only be created by an
// administrator or as the first account.
func (a Admins) Reserves(name string) bool {
	folded := FoldName(name)
	return slices.ContainsFunc(a, func(n string) bool { return FoldName(n) == folded })
}

// Manages reports whether the start-up rule keeps acc an administrator
// (is_config_managed_admin): an exact entry for a local administrator.
func (a Admins) Manages(acc Account) bool {
	return acc.IsAdmin && acc.Managed == ManagedLocal && slices.Contains(a, acc.Username)
}

// pyISO renders t like Python's naive datetime.isoformat() in UTC.
func pyISO(t time.Time) string {
	t = t.UTC()
	if t.Nanosecond()/1000 == 0 {
		return t.Format("2006-01-02T15:04:05")
	}
	return t.Format("2006-01-02T15:04:05.000000")
}
