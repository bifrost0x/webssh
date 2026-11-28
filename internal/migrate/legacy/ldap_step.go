package legacy

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strconv"

	"github.com/bifrost0x/webssh/internal/accounts"
	"github.com/bifrost0x/webssh/internal/auth/ldap"
	"github.com/bifrost0x/webssh/internal/store"
)

// AddLDAP registers the steps of the area "ldap": the LDAP identities
// (E03) and the revocation fences (E37). They take over the entities the
// M1 release keeps in place.
func AddLDAP(r *Registry) error {
	r.Schemas(ldap.Schema())
	return errors.Join(
		r.Add(GroupFactors, func() Step { return &ldapIdentitiesStep{} }),
		r.Add(GroupFactors, func() Step { return &ldapFencesStep{} }),
	)
}

// LDAPIdentityRow is one row of ldap_identities.
type LDAPIdentityRow struct {
	ID                int64
	UserID            int64
	Provider          string
	Subject           string
	DirectoryUsername string
	DistinguishedName string
	CreatedAt         sql.NullString
	LastVerifiedAt    sql.NullString
}

// LDAPIdentities reads ldap_identities by id.
func (s *Source) LDAPIdentities(ctx context.Context) ([]LDAPIdentityRow, error) {
	if !s.schema.HasTable("ldap_identities") {
		return nil, nil
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, user_id, CAST(provider AS TEXT), CAST(subject AS TEXT),
		CAST(directory_username AS TEXT), CAST(distinguished_name AS TEXT), CAST(created_at AS TEXT),
		CAST(last_verified_at AS TEXT) FROM ldap_identities ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("legacy: read LDAP identities: %w", err)
	}
	defer rows.Close()
	var out []LDAPIdentityRow
	for rows.Next() {
		var r LDAPIdentityRow
		if err := rows.Scan(&r.ID, &r.UserID, &r.Provider, &r.Subject, &r.DirectoryUsername, &r.DistinguishedName,
			&r.CreatedAt, &r.LastVerifiedAt); err != nil {
			return nil, fmt.Errorf("legacy: read LDAP identities: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ldapIdentitiesStep migrates entity E03 verbatim: id, account, provider
// and the canonical subject, which together are the binding a directory
// sign-in resolves, plus the directory name, the DN and both times. A row
// whose account does not exist is not migrated and is flagged: a later
// account with that id would otherwise inherit the identity. Duplicate
// bindings stop the migration (the unique keys of the table).
type ldapIdentitiesStep struct {
	rows    []ldap.Identity
	orphans []Flag
	// truncated are migrated bindings whose subject the Python release
	// may have cut at a NUL byte (ldap.SubjectMayBeTruncated).
	truncated []ldap.Identity
}

func (*ldapIdentitiesStep) Entity() string { return "E03" }

func (*ldapIdentitiesStep) Version() int { return 1 }

func (s *ldapIdentitiesStep) Read(ctx context.Context, src *Source) error {
	rows, err := src.LDAPIdentities(ctx)
	if err != nil {
		return err
	}
	_, ids, err := accountIDs(ctx, src)
	if err != nil {
		return err
	}
	for _, r := range rows {
		if !ids[r.UserID] {
			s.orphans = append(s.orphans, Flag{UserID: r.UserID, ID: strconv.FormatInt(r.ID, 10), Reason: "LDAP identity of a missing account, not migrated"})
			continue
		}
		id := ldap.Identity{ID: r.ID, UserID: r.UserID, Provider: r.Provider, Subject: r.Subject,
			DirectoryUsername: r.DirectoryUsername, DistinguishedName: r.DistinguishedName}
		if id.CreatedAt, err = dbTime(r.CreatedAt); err == nil {
			id.LastVerifiedAt, err = dbTime(r.LastVerifiedAt)
		}
		if err != nil {
			return &StepError{UserID: r.UserID, Record: strconv.FormatInt(r.ID, 10), Err: err}
		}
		s.rows = append(s.rows, id)
		if ldap.SubjectMayBeTruncated(id.Subject) {
			s.truncated = append(s.truncated, id)
		}
	}
	return nil
}

func (s *ldapIdentitiesStep) Write(ctx context.Context, tx *store.Tx, _ Sealer) error {
	for _, id := range s.rows {
		if err := ldap.ImportIdentityTx(ctx, tx, id); err != nil {
			return &StepError{UserID: id.UserID, Record: strconv.FormatInt(id.ID, 10),
				Err: fmt.Errorf("legacy: LDAP identity not unique or unreadable: %w", err)}
		}
	}
	return nil
}

// Verify reads the rows back and resolves every binding the way a
// directory sign-in does: (provider, subject) must lead to the same
// account, and that account must be managed by LDAP.
func (s *ldapIdentitiesStep) Verify(ctx context.Context, tx *store.Tx, _ Opener) error {
	got, err := ldap.IdentitiesTx(ctx, tx)
	if err != nil {
		return err
	}
	if !slices.EqualFunc(got, s.rows, sameLDAPIdentity) {
		return &StepError{Err: errors.New("legacy: the stored LDAP identities differ")}
	}
	for _, id := range s.rows {
		userID, err := ldap.AccountOfTx(ctx, tx, id.Provider, id.Subject)
		if err != nil || userID != id.UserID {
			return &StepError{UserID: id.UserID, Record: strconv.FormatInt(id.ID, 10),
				Err: errors.Join(errors.New("legacy: the LDAP binding resolves to another account"), err)}
		}
		acc, err := accounts.GetTx(ctx, tx, id.UserID)
		if err != nil || acc.Managed != accounts.ManagedLDAP {
			return &StepError{UserID: id.UserID, Err: errors.Join(errors.New("legacy: the LDAP account is not LDAP-managed"), err)}
		}
	}
	return nil
}

func sameLDAPIdentity(a, b ldap.Identity) bool {
	return a.ID == b.ID && a.UserID == b.UserID && a.Provider == b.Provider && a.Subject == b.Subject &&
		a.DirectoryUsername == b.DirectoryUsername && a.DistinguishedName == b.DistinguishedName &&
		a.CreatedAt.Equal(b.CreatedAt) && a.LastVerifiedAt.Equal(b.LastVerifiedAt)
}

// Report names, beside the orphans, every binding with a possibly
// truncated subject. It keeps signing in for its own DN; another
// directory entry with the same short subject is refused (audit
// ambiguous_subject) and the account needs a relink (finding #40).
func (s *ldapIdentitiesStep) Report() StepReport {
	r := StepReport{Entity: "E03", Version: 1, Read: len(s.rows) + len(s.orphans), Written: len(s.rows),
		Flagged: slices.Clone(s.orphans)}
	for _, id := range s.truncated {
		r.Flagged = append(r.Flagged, Flag{UserID: id.UserID, ID: strconv.FormatInt(id.ID, 10),
			Reason: "LDAP binding may stem from a truncated binary unique ID"})
		r.Warnings = append(r.Warnings, Warning{Code: "ldap_subject_truncated", UserID: id.UserID,
			Message: fmt.Sprintf("The LDAP binding %d (provider %q, %s) has a subject 3.3 may have cut at a NUL byte of a binary unique ID such as objectGUID. "+
				"It still signs in for this DN; if another directory entry is refused with ambiguous_subject, relink the account.",
				id.ID, id.Provider, id.DistinguishedName)})
	}
	return r
}

// ldapFencesDir is the fence directory of app/ldap_session.py.
const ldapFencesDir = ".ldap-revocation-fences"

// ldapFences are the accounts Python denied until a directory check:
// every entry of DATA_DIR/.ldap-revocation-fences named by the decimal id
// of an account, of any file type (Python checked with lstat). When the
// directory exists but cannot be read, Python denied every LDAP account.
type ldapFences struct {
	fenced     []int64
	unreadable bool
	ignored    int
	entries    int
}

func readLDAPFences(ctx context.Context, src *Source, ids map[int64]bool) (ldapFences, error) {
	var f ldapFences
	entries, err := fs.ReadDir(src.root.FS(), ldapFencesDir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return f, nil
	case err != nil:
		f.unreadable = true
		identities, err := src.LDAPIdentities(ctx)
		if err != nil {
			return f, err
		}
		for _, id := range identities {
			if ids[id.UserID] && !slices.Contains(f.fenced, id.UserID) {
				f.fenced = append(f.fenced, id.UserID)
			}
		}
		slices.Sort(f.fenced)
		return f, nil
	}
	f.entries = len(entries)
	for _, e := range entries {
		id, err := strconv.ParseInt(e.Name(), 10, 64)
		if err != nil || id <= 0 || strconv.FormatInt(id, 10) != e.Name() || !ids[id] {
			f.ignored++
			continue
		}
		f.fenced = append(f.fenced, id)
	}
	slices.Sort(f.fenced)
	return f, nil
}

// ldapFencesStep migrates entity E37. A fence marks a revalidation or
// invalidation whose outcome Python did not record before it stopped;
// Python denied access until the directory was checked again. The
// accounts step raises the auth generation of each fenced account (every
// old credential ends); this step makes a directory check required before
// any access, which the next LDAP sign-in is. The files stay in place.
type ldapFencesStep struct {
	ldapFences
	legacy map[int64]int64
}

func (*ldapFencesStep) Entity() string { return "E37" }

func (*ldapFencesStep) Version() int { return 1 }

func (s *ldapFencesStep) Read(ctx context.Context, src *Source) error {
	rows, ids, err := accountIDs(ctx, src)
	if err != nil {
		return err
	}
	if s.ldapFences, err = readLDAPFences(ctx, src, ids); err != nil {
		return err
	}
	s.legacy = map[int64]int64{}
	for _, r := range rows {
		s.legacy[r.ID] = r.AuthGeneration
	}
	return nil
}

func (s *ldapFencesStep) Write(ctx context.Context, tx *store.Tx, _ Sealer) error {
	for _, id := range s.fenced {
		if err := ldap.RequireRevalidationTx(ctx, tx, id); err != nil {
			return &StepError{UserID: id, Err: err}
		}
	}
	return nil
}

// Verify checks that every fenced account has its generation raised by
// one over the legacy value and is refused until a directory check
// succeeds.
func (s *ldapFencesStep) Verify(ctx context.Context, tx *store.Tx, _ Opener) error {
	for _, id := range s.fenced {
		acc, err := accounts.GetTx(ctx, tx, id)
		if err != nil {
			return &StepError{UserID: id, Err: err}
		}
		required, _, err := ldap.RevalidationTx(ctx, tx, id)
		if err != nil || !required || acc.AuthGeneration != s.legacy[id]+1 {
			return &StepError{UserID: id, Err: errors.Join(errors.New("legacy: the LDAP fence was not carried over"), err)}
		}
	}
	return nil
}

func (s *ldapFencesStep) Report() StepReport {
	r := StepReport{Entity: "E37", Version: 1, Read: len(s.fenced) + s.ignored, Written: len(s.fenced)}
	switch {
	case s.unreadable:
		r.KeptInPlace = []KeptPath{{Path: ldapFencesDir, Reason: "LDAP revocation fences (unreadable)"}}
	case s.entries > 0:
		r.KeptInPlace = []KeptPath{{Path: ldapFencesDir, Reason: "LDAP revocation fences", Files: s.entries}}
	}
	for _, id := range s.fenced {
		r.Flagged = append(r.Flagged, Flag{UserID: id, Reason: "LDAP revocation fence: signed out, the next sign-in checks the directory"})
	}
	if s.unreadable {
		r.Warnings = append(r.Warnings, Warning{Code: "ldap_fences_unreadable",
			Message: "The LDAP revocation fences could not be read; every LDAP account must sign in again."})
	}
	if s.ignored > 0 {
		r.Notes = append(r.Notes, fmt.Sprintf("%d entries of %s name no account and were ignored, as Python ignored them", s.ignored, ldapFencesDir))
	}
	return r
}
