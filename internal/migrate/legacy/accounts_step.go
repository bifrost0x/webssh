package legacy

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/bifrost0x/webssh/internal/accounts"
	"github.com/bifrost0x/webssh/internal/auth"
	"github.com/bifrost0x/webssh/internal/store"
)

// accountsStep migrates entity E01: every account with its id, its name
// byte for byte, the frozen incarnation and history generation (4.2),
// the admin flag after Python's start-up rules (4.6), the lock, the
// generation, the MFA flag and the code backoff counters. The manager
// (LDAP, GitHub) is derived from the identities.
type accountsStep struct {
	admins []string

	accounts       []importedAccount
	promoted       []string // names promoted by the start-up rules
	missing        []string // ADMIN_USERS names without an account
	orphans        []string // user directories without an account
	orphanFloor    int64    // highest id of such a directory
	implausible    []string // such directories with an id above maxDirectoryID
	missingColumns []string
}

type importedAccount struct {
	acc                   accounts.Account
	login, stepUp         int64
	loginLast, stepUpLast time.Time
	noIncarnation         bool
}

func (*accountsStep) Entity() string { return "E01" }

func (*accountsStep) Version() int { return 1 }

func (s *accountsStep) Read(ctx context.Context, src *Source) error {
	rows, ids, err := accountIDs(ctx, src)
	if err != nil {
		return err
	}
	managed, err := managers(ctx, src)
	if err != nil {
		return err
	}
	fences, err := readLDAPFences(ctx, src, ids)
	if err != nil {
		return err
	}
	s.missingColumns = src.Schema().MissingUserColumns()
	for _, r := range rows {
		a, err := convertAccount(r, managed[r.ID])
		if err != nil {
			return &StepError{UserID: r.ID, Err: err}
		}
		if slices.Contains(fences.fenced, r.ID) {
			// An LDAP revocation fence (E37): every credential issued
			// before the interrupted invalidation ends.
			a.acc.AuthGeneration++
		}
		s.accounts = append(s.accounts, a)
	}
	s.promoted, s.missing = applyStartupAdminRules(s.accounts, s.admins)
	dirs, err := src.UserDirectories()
	if err != nil {
		return err
	}
	for _, d := range dirs {
		id, err := strconv.ParseInt(strings.TrimPrefix(d, "user_"), 10, 64)
		if err != nil || !strings.HasPrefix(d, "user_") || !ids[id] {
			s.orphans = append(s.orphans, "users/"+d)
		}
		switch {
		case err != nil || !strings.HasPrefix(d, "user_") || ids[id] || id <= 0:
		case id > maxDirectoryID:
			s.implausible = append(s.implausible, "users/"+d)
		default:
			// Legacy data exists for this id; it is never handed out again
			// (specification 4.1).
			s.orphanFloor = max(s.orphanFloor, id)
		}
	}
	return nil
}

// managers derives accounts_users.managed_by from the identities:
// is_ldap_managed (any LDAP identity) wins over is_github_managed (a
// GitHub identity provisioned by GitHub sign-in), as app/models.py
// checks them in that order.
func managers(ctx context.Context, src *Source) (map[int64]accounts.Manager, error) {
	ids, err := src.ExternalIdentities(ctx)
	if err != nil {
		return nil, err
	}
	out := map[int64]accounts.Manager{}
	for _, e := range ids {
		switch {
		case e.Provider == "ldap":
			out[e.UserID] = accounts.ManagedLDAP
		case e.Provider == "github" && e.Provisioned && out[e.UserID] == accounts.ManagedLocal:
			out[e.UserID] = accounts.ManagedGitHub
		}
	}
	return out, nil
}

func convertAccount(r AccountRow, managed accounts.Manager) (importedAccount, error) {
	a := importedAccount{acc: accounts.Account{ID: r.ID, Username: r.Username, IsAdmin: r.IsAdmin, IsLocked: r.IsLocked,
		AuthGeneration: r.AuthGeneration, MFARequired: r.MFAEnabled, Managed: managed}}
	var err error
	if r.CreatedAt.Valid {
		if a.acc.Incarnation, err = r.Incarnation(); err != nil {
			return a, err
		}
		a.acc.HistoryGeneration = a.acc.Incarnation
	} else {
		// app/browser_identity.py falls back to the password hash.
		a.acc.HistoryGeneration, a.noIncarnation = r.PasswordHash, true
	}
	if a.acc.CreatedAt, err = dbTime(r.CreatedAt); err != nil {
		return a, err
	}
	if a.acc.LastLogin, err = dbTime(r.LastLogin); err != nil {
		return a, err
	}
	if r.MFAFailedAttempts < 0 || r.StepUpFailedAttempts < 0 {
		return a, errors.New("legacy: negative code backoff counter")
	}
	a.login, a.stepUp = r.MFAFailedAttempts, r.StepUpFailedAttempts
	if a.loginLast, err = dbTime(r.MFALastFailedAt); err != nil {
		return a, err
	}
	if a.stepUpLast, err = dbTime(r.StepUpLastFailedAt); err != nil {
		return a, err
	}
	return a, nil
}

// applyStartupAdminRules applies, in memory and in Python's order,
// ensure_initial_admin and sync_admin_users (app/auth.py). It returns the
// promoted names and the listed names without an account.
func applyStartupAdminRules(list []importedAccount, admins []string) (promoted, missing []string) {
	local := func(a importedAccount) bool { return a.acc.Managed == accounts.ManagedLocal }
	if !slices.ContainsFunc(list, func(a importedAccount) bool { return a.acc.IsAdmin && local(a) }) {
		if i := slices.IndexFunc(list, local); i >= 0 {
			list[i].acc.IsAdmin = true
			promoted = append(promoted, list[i].acc.Username)
		}
	}
	for _, name := range admins {
		i := slices.IndexFunc(list, func(a importedAccount) bool { return a.acc.Username == name })
		if i < 0 {
			missing = append(missing, name)
			continue
		}
		if a := &list[i].acc; !a.IsAdmin && !a.IsLocked && a.Managed == accounts.ManagedLocal {
			a.IsAdmin = true
			promoted = append(promoted, a.Username)
		}
	}
	return promoted, missing
}

func (s *accountsStep) Write(ctx context.Context, tx *store.Tx, _ Sealer) error {
	if err := (&accounts.Service{}).RaiseIDFloorTx(ctx, tx, s.orphanFloor); err != nil {
		return err
	}
	for _, a := range s.accounts {
		if err := accounts.ImportTx(ctx, tx, a.acc); err != nil {
			return &StepError{UserID: a.acc.ID, Err: err}
		}
		if err := errors.Join(auth.ImportThrottleTx(ctx, tx, a.acc.ID, auth.ScopeLogin, int(a.login), a.loginLast),
			auth.ImportThrottleTx(ctx, tx, a.acc.ID, auth.ScopeStepUp, int(a.stepUp), a.stepUpLast)); err != nil {
			return &StepError{UserID: a.acc.ID, Err: err}
		}
	}
	return nil
}

func (s *accountsStep) Verify(ctx context.Context, tx *store.Tx, _ Opener) error {
	var highest int64
	for _, want := range s.accounts {
		got, err := accounts.GetTx(ctx, tx, want.acc.ID)
		if err != nil {
			return &StepError{UserID: want.acc.ID, Err: err}
		}
		if !sameAccount(got, want.acc) {
			return &StepError{UserID: want.acc.ID, Err: errors.New("legacy: the stored account differs")}
		}
		for _, c := range []struct {
			scope auth.Scope
			n     int64
			last  time.Time
		}{{auth.ScopeLogin, want.login, want.loginLast}, {auth.ScopeStepUp, want.stepUp, want.stepUpLast}} {
			n, last, err := auth.ThrottleTx(ctx, tx, want.acc.ID, c.scope)
			if errors.Is(err, sql.ErrNoRows) {
				n, err = 0, nil
			}
			wantLast := int64(0)
			if c.n > 0 && !c.last.IsZero() {
				wantLast = c.last.UnixMicro()
			}
			if err != nil || int64(n) != c.n || (c.n > 0 && last != wantLast) {
				return &StepError{UserID: want.acc.ID, Err: errors.Join(fmt.Errorf("legacy: code backoff %s differs", c.scope), err)}
			}
		}
		highest = max(highest, want.acc.ID)
	}
	floor, err := accounts.IDFloorTx(ctx, tx)
	if err != nil {
		return err
	}
	if highest = max(highest, s.orphanFloor); floor < highest {
		return fmt.Errorf("legacy: id floor %d is below the highest account id %d", floor, highest)
	}
	return nil
}

func sameAccount(got, want accounts.Account) bool {
	return got.ID == want.ID && got.Username == want.Username && got.Incarnation == want.Incarnation &&
		got.HistoryGeneration == want.HistoryGeneration && got.CreatedAt.Equal(want.CreatedAt) &&
		got.LastLogin.Equal(want.LastLogin) && got.IsAdmin == want.IsAdmin && got.IsLocked == want.IsLocked &&
		got.AuthGeneration == want.AuthGeneration && got.MFARequired == want.MFARequired && got.Managed == want.Managed
}

func (s *accountsStep) Report() StepReport {
	r := StepReport{Entity: "E01", Version: 1, Read: len(s.accounts), Written: len(s.accounts)}
	if len(s.missingColumns) > 0 {
		r.Notes = append(r.Notes, "columns added with Python's defaults: "+strings.Join(s.missingColumns, ", "))
	}
	for _, a := range s.accounts {
		if a.noIncarnation {
			r.Flagged = append(r.Flagged, Flag{UserID: a.acc.ID, Reason: "no_creation_time: saved passwords and the automation vault stay unavailable, as in the Python release"})
		}
		if a.acc.IsLocked {
			r.Notes = append(r.Notes, fmt.Sprintf("account %d is locked and stays locked", a.acc.ID))
		}
	}
	for _, name := range s.promoted {
		r.Warnings = append(r.Warnings, Warning{Code: "admin_promoted_at_migration",
			Message: "the account " + strconv.Quote(name) + " became an administrator by the start-up rules the Python release applies at its next start"})
	}
	for _, name := range s.missing {
		r.Warnings = append(r.Warnings, Warning{Code: "admin_user_missing",
			Message: "ADMIN_USERS lists " + strconv.Quote(name) + ", which has no account; registration refuses this name"})
	}
	if s.orphanFloor > 0 {
		r.Notes = append(r.Notes, fmt.Sprintf("new account ids start above %d, the highest id of a user directory without an account", s.orphanFloor))
	}
	for _, p := range s.implausible {
		r.Notes = append(r.Notes, fmt.Sprintf("%s: the id is above %d and does not raise the id floor", p, maxDirectoryID))
	}
	for _, p := range s.orphans {
		r.KeptInPlace = append(r.KeptInPlace, KeptPath{Path: p, Reason: "user_directory_without_account"})
	}
	return r
}
