package github

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/bifrost0x/webssh/internal/auth"
	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/store"
)

// Identity is one row of authgithub_identities (github_identities).
type Identity struct {
	ID           int64
	UserID       int64
	GitHubUserID string
	Login        string
	DisplayName  string // "" for NULL
	HasName      bool
	Provisioned  bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
	// LastVerifiedAt is zero for NULL.
	LastVerifiedAt time.Time
}

const identityColumns = `id, user_id, github_user_id, login, display_name, provisioned, created_us, updated_us, last_verified_us`

func scanIdentity(row interface{ Scan(...any) error }) (Identity, error) {
	var i Identity
	var name sql.NullString
	var created, updated int64
	var verified sql.NullInt64
	if err := row.Scan(&i.ID, &i.UserID, &i.GitHubUserID, &i.Login, &name, &i.Provisioned, &created, &updated, &verified); err != nil {
		return Identity{}, err
	}
	i.DisplayName, i.HasName = name.String, name.Valid
	i.CreatedAt, i.UpdatedAt = time.UnixMicro(created).UTC(), time.UnixMicro(updated).UTC()
	if verified.Valid {
		i.LastVerifiedAt = time.UnixMicro(verified.Int64).UTC()
	}
	return i, nil
}

func identityWhereTx(ctx context.Context, tx *store.Tx, where string, arg any) (Identity, bool, error) {
	i, err := scanIdentity(tx.QueryRowContext(ctx, `SELECT `+identityColumns+` FROM authgithub_identities WHERE `+where, arg))
	if errors.Is(err, sql.ErrNoRows) {
		return Identity{}, false, nil
	}
	if err != nil {
		return Identity{}, false, fmt.Errorf("github: read identity: %w", err)
	}
	return i, true, nil
}

// IdentityOfTx returns the GitHub identity of an account, if any.
func IdentityOfTx(ctx context.Context, tx *store.Tx, userID int64) (Identity, bool, error) {
	return identityWhereTx(ctx, tx, `user_id = ?`, userID)
}

func byGitHubTx(ctx context.Context, tx *store.Tx, githubUserID string) (Identity, bool, error) {
	return identityWhereTx(ctx, tx, `github_user_id = ?`, githubUserID)
}

var errIdentityLinked = fault.New(fault.Conflict, "GitHub identity is already linked")

// insertTx stores a new identity. An account with an identity or a GitHub
// id that is linked already is fault.Conflict; writes are serialized, so
// the check and the insert cannot race.
func insertTx(ctx context.Context, tx *store.Tx, i Identity) (Identity, error) {
	if _, found, err := IdentityOfTx(ctx, tx, i.UserID); err != nil || found {
		return Identity{}, errors.Join(err, conflictIf(found))
	}
	if _, found, err := byGitHubTx(ctx, tx, i.GitHubUserID); err != nil || found {
		return Identity{}, errors.Join(err, conflictIf(found))
	}
	var name sql.NullString
	if i.HasName {
		name = sql.NullString{String: i.DisplayName, Valid: true}
	}
	var verified sql.NullInt64
	if !i.LastVerifiedAt.IsZero() {
		verified = sql.NullInt64{Int64: i.LastVerifiedAt.UnixMicro(), Valid: true}
	}
	query := `INSERT INTO authgithub_identities (user_id, github_user_id, login, display_name, provisioned, created_us, updated_us, last_verified_us)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?) RETURNING id`
	args := []any{i.UserID, i.GitHubUserID, i.Login, name, i.Provisioned, i.CreatedAt.UnixMicro(), i.UpdatedAt.UnixMicro(), verified}
	if i.ID > 0 {
		query = `INSERT INTO authgithub_identities (id, user_id, github_user_id, login, display_name, provisioned, created_us, updated_us, last_verified_us)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id`
		args = append([]any{i.ID}, args...)
	}
	if err := tx.QueryRowContext(ctx, query, args...).Scan(&i.ID); err != nil {
		return Identity{}, fmt.Errorf("github: store identity: %w", err)
	}
	return i, nil
}

func conflictIf(found bool) error {
	if found {
		return errIdentityLinked
	}
	return nil
}

func (s *Service) newIdentity(userID int64, p Profile, provisioned bool) Identity {
	now := s.now().Truncate(time.Microsecond)
	return Identity{UserID: userID, GitHubUserID: p.UserID, Login: p.Login, DisplayName: p.DisplayName,
		HasName: p.DisplayName != "", Provisioned: provisioned, CreatedAt: now, UpdatedAt: now, LastVerifiedAt: now}
}

// touchTx records a sign-in: login and name as GitHub shows them now.
func (s *Service) touchTx(ctx context.Context, tx *store.Tx, id int64, p Profile) error {
	now := s.now().UnixMicro()
	var name sql.NullString
	if p.DisplayName != "" {
		name = sql.NullString{String: p.DisplayName, Valid: true}
	}
	_, err := tx.ExecContext(ctx, `UPDATE authgithub_identities SET login = ?, display_name = ?, last_verified_us = ?, updated_us = ? WHERE id = ?`,
		p.Login, name, now, now, id)
	if err != nil {
		return fmt.Errorf("github: update identity: %w", err)
	}
	return nil
}

func profileOf(id auth.Identity) Profile {
	return Profile{UserID: id.Subject, Login: id.Username, DisplayName: id.DisplayName}
}

func linked(i Identity) auth.LinkedIdentity {
	return auth.LinkedIdentity{ID: i.ID, UserID: i.UserID, Provider: auth.ProviderGitHub, Subject: i.GitHubUserID,
		Username: i.Login, Provisioned: i.Provisioned, CreatedAt: i.CreatedAt, LastVerifiedAt: i.LastVerifiedAt}
}

// Account implements auth.IdentityLinks: the account linked to the
// numeric GitHub id, or fault.NotFound.
func (s *Service) Account(ctx context.Context, id auth.Identity) (int64, error) {
	var i Identity
	var found bool
	err := s.DB.Read(ctx, func(tx *store.Tx) error {
		var err error
		i, found, err = byGitHubTx(ctx, tx, id.Subject)
		return err
	})
	switch {
	case err != nil:
		return 0, fault.Wrap(fault.StorageError, err, "")
	case !found:
		return 0, fault.New(fault.NotFound, "")
	}
	return i.UserID, nil
}

// Provision implements auth.IdentityLinks with the configured policy.
func (s *Service) Provision(ctx context.Context, id auth.Identity) (int64, error) {
	cfg, err := s.Configuration(ctx)
	if err != nil {
		return 0, err
	}
	if !cfg.AutoProvision || s.unrestricted(cfg.AutoProvision, cfg.AllowedOrgs) {
		return 0, fault.New(fault.Forbidden, "")
	}
	acc, err := s.provision(ctx, profileOf(id))
	return acc.UserID, err
}

// LinkTx implements auth.IdentityLinks.
func (s *Service) LinkTx(ctx context.Context, tx *store.Tx, userID int64, id auth.Identity) (auth.LinkedIdentity, error) {
	i, err := insertTx(ctx, tx, s.newIdentity(userID, profileOf(id), false))
	if err != nil {
		return auth.LinkedIdentity{}, err
	}
	return linked(i), nil
}

// Unlink implements auth.IdentityLinks for the account's own identity; the
// browser flow uses the HTTP route, which also renews the sessions.
func (s *Service) Unlink(ctx context.Context, userID, identityID int64) error {
	return s.DB.Write(ctx, func(tx *store.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM authgithub_identities WHERE id = ? AND user_id = ?`, identityID, userID)
		if err != nil {
			return fmt.Errorf("github: delete identity: %w", err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return fault.New(fault.NotFound, "No GitHub identity is linked")
		}
		return nil
	})
}

// List implements auth.IdentityLinks.
func (s *Service) List(ctx context.Context, userID int64) ([]auth.LinkedIdentity, error) {
	var out []auth.LinkedIdentity
	err := s.DB.Read(ctx, func(tx *store.Tx) error {
		i, found, err := IdentityOfTx(ctx, tx, userID)
		if found {
			out = append(out, linked(i))
		}
		return err
	})
	if err != nil {
		return nil, fault.Wrap(fault.StorageError, err, "")
	}
	return out, nil
}

// Identity returns the account's GitHub identity, if any.
func (s *Service) Identity(ctx context.Context, userID int64) (Identity, bool, error) {
	var i Identity
	var found bool
	err := s.DB.Read(ctx, func(tx *store.Tx) error {
		var err error
		i, found, err = IdentityOfTx(ctx, tx, userID)
		return err
	})
	if err != nil {
		return Identity{}, false, fault.Wrap(fault.StorageError, err, "")
	}
	return i, found, nil
}
