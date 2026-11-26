package accounts

import (
	"context"
	"fmt"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/store"
)

// maxProvisionedRunes bounds names a provider hands in; the providers
// apply their own, stricter rules first (LDAP: 64 characters, GitHub: 32).
const maxProvisionedRunes = 255

// Refusals of ProvisionTx.
var (
	ErrProvisionName     = fault.New(fault.InvalidValue, "The account name cannot be provisioned")
	ErrProvisionTaken    = fault.New(fault.Conflict, "Username already exists")
	errProvisionManager  = fault.New(fault.InvalidValue, "")
	errProvisionInternal = fault.New(fault.Internal, "")
)

// ProvisionTx creates an account managed by an external provider inside
// the provider's write transaction, so the account and its identity link
// commit together (M2 contracts, "Managed accounts"). manager is "ldap" or
// "github". The account has no local password, is never an administrator
// and is not locked. A name that equals an existing one under case
// folding is ErrProvisionTaken. A name listed in ADMIN_USERS may be
// provisioned: the start-up rule never promotes a managed account, and
// converting it to a local one is refused (CheckLocalConversion).
func (s *Service) ProvisionTx(ctx context.Context, tx *store.Tx, username, manager string) (int64, error) {
	m := Manager(manager)
	if m != ManagedLDAP && m != ManagedGitHub {
		return 0, errProvisionManager
	}
	if username == "" || !utf8.ValidString(username) || utf8.RuneCountInString(username) > maxProvisionedRunes {
		return 0, ErrProvisionName
	}
	for _, r := range username {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Co, r) || unicode.Is(unicode.Cs, r) {
			return 0, ErrProvisionName
		}
	}
	_, names, err := existing(ctx, tx)
	if err != nil {
		return 0, err
	}
	folded := FoldName(username)
	for _, n := range names {
		if FoldName(n) == folded {
			return 0, ErrProvisionTaken
		}
	}
	var id int64
	if err := tx.QueryRowContext(ctx, `SELECT max((SELECT coalesce(max(id), 0) FROM accounts_users),
		(SELECT value FROM accounts_id_floor WHERE singleton = 1)) + 1`).Scan(&id); err != nil {
		return 0, fmt.Errorf("accounts: next id: %w", err)
	}
	if id <= 0 {
		return 0, errProvisionInternal
	}
	now := s.now()
	inc := pyISO(now)
	if _, err := tx.ExecContext(ctx, `INSERT INTO accounts_users (id, username, incarnation, history_generation, created_us, managed_by)
		VALUES (?, ?, ?, ?, ?, ?)`, id, username, inc, inc, now.Truncate(time.Microsecond).UnixMicro(), manager); err != nil {
		return 0, fmt.Errorf("accounts: provision: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE accounts_id_floor SET value = ? WHERE singleton = 1`, id); err != nil {
		return 0, fmt.Errorf("accounts: raise id floor: %w", err)
	}
	return id, nil
}
