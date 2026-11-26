package legacy

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/bifrost0x/webssh/internal/auth/github"
	"github.com/bifrost0x/webssh/internal/store"
)

// githubIdentitiesStep migrates entity E04 into internal/auth/github:
// every github_identities row verbatim, keyed by the numeric GitHub user
// id. provisioned_by_github keeps the managed-account rule (E01 derives
// managed_by from it). A row whose account does not exist is not taken
// over and is reported; Python ignores it as well.
type githubIdentitiesStep struct {
	rows    []github.Identity
	orphans []Flag
}

func (*githubIdentitiesStep) Entity() string { return "E04" }

func (*githubIdentitiesStep) Version() int { return 1 }

func (s *githubIdentitiesStep) Read(ctx context.Context, src *Source) error {
	if !src.schema.HasTable("github_identities") {
		return nil
	}
	_, ids, err := accountIDs(ctx, src)
	if err != nil {
		return err
	}
	last := "NULL"
	if src.schema.HasColumn("github_identities", "last_verified_at") {
		last = "CAST(last_verified_at AS TEXT)"
	}
	provisioned := "0"
	if src.schema.HasColumn("github_identities", "provisioned_by_github") {
		provisioned = "provisioned_by_github"
	}
	rows, err := src.db.QueryContext(ctx, `SELECT id, user_id, CAST(github_user_id AS TEXT), login, display_name, `+provisioned+`,
		CAST(created_at AS TEXT), CAST(updated_at AS TEXT), `+last+` FROM github_identities ORDER BY id`) // #nosec G202 -- constant column choices
	if err != nil {
		return fmt.Errorf("legacy: read GitHub identities: %w", err)
	}
	defer rows.Close()
	seenUser, seenID := map[int64]bool{}, map[string]bool{}
	for rows.Next() {
		var i github.Identity
		var name, created, updated, verified sql.NullString
		if err := rows.Scan(&i.ID, &i.UserID, &i.GitHubUserID, &i.Login, &name, &i.Provisioned, &created, &updated, &verified); err != nil {
			return fmt.Errorf("legacy: read GitHub identities: %w", err)
		}
		i.DisplayName, i.HasName = name.String, name.Valid
		rec := fmt.Sprint(i.ID)
		if i.CreatedAt, err = dbTime(created); err == nil {
			if i.UpdatedAt, err = dbTime(updated); err == nil {
				i.LastVerifiedAt, err = dbTime(verified)
			}
		}
		if err == nil && (!created.Valid || !updated.Valid) {
			err = errors.New("legacy: GitHub identity without timestamps")
		}
		if err != nil {
			return &StepError{UserID: i.UserID, Record: rec, Err: err}
		}
		if seenUser[i.UserID] || seenID[i.GitHubUserID] || i.GitHubUserID == "" {
			return &StepError{UserID: i.UserID, Record: rec, Err: errors.New("legacy: GitHub identity is not unique")}
		}
		seenUser[i.UserID], seenID[i.GitHubUserID] = true, true
		if !ids[i.UserID] {
			s.orphans = append(s.orphans, Flag{UserID: i.UserID, ID: rec, Reason: "github_identity_without_account"})
			continue
		}
		s.rows = append(s.rows, i)
	}
	return rows.Err()
}

func (s *githubIdentitiesStep) Write(ctx context.Context, tx *store.Tx, _ Sealer) error {
	for _, i := range s.rows {
		if err := github.ImportIdentityTx(ctx, tx, i); err != nil {
			return &StepError{UserID: i.UserID, Record: fmt.Sprint(i.ID), Err: err}
		}
	}
	return nil
}

func (s *githubIdentitiesStep) Verify(ctx context.Context, tx *store.Tx, _ Opener) error {
	got, err := github.IdentitiesTx(ctx, tx)
	if err != nil {
		return err
	}
	if !slices.EqualFunc(got, s.rows, sameGitHubIdentity) {
		return errors.New("legacy: the stored GitHub identities differ")
	}
	return nil
}

func sameGitHubIdentity(a, b github.Identity) bool {
	return a.ID == b.ID && a.UserID == b.UserID && a.GitHubUserID == b.GitHubUserID && a.Login == b.Login &&
		a.DisplayName == b.DisplayName && a.HasName == b.HasName && a.Provisioned == b.Provisioned &&
		a.CreatedAt.Equal(b.CreatedAt) && a.UpdatedAt.Equal(b.UpdatedAt) && a.LastVerifiedAt.Equal(b.LastVerifiedAt)
}

func (s *githubIdentitiesStep) Report() StepReport {
	return StepReport{Entity: "E04", Version: 1, Read: len(s.rows) + len(s.orphans), Written: len(s.rows), Flagged: s.orphans}
}

// githubConfigStep migrates entity E06: the single configuration row, the
// client secret decrypted with the legacy derivation and sealed with the
// keyring; redirect_uri unchanged (invariant I-03). A secret that does not
// decrypt stops the migration.
type githubConfigStep struct {
	cfg   github.ImportedConfig
	found bool
}

func (*githubConfigStep) Entity() string { return "E06" }

func (*githubConfigStep) Version() int { return 1 }

func (s *githubConfigStep) Read(ctx context.Context, src *Source) error {
	c, err := src.GitHubConfiguration(ctx)
	if err != nil || c == nil {
		return err
	}
	s.found = true
	s.cfg = github.ImportedConfig{Enabled: c.Enabled, ClientID: c.ClientID, RedirectURI: c.RedirectURI,
		AutoProvision: c.AutoProvision, AllowedOrgs: c.AllowedOrgs, Generation: c.Generation}
	if c.ClientSecret != "" {
		s.cfg.ClientSecret = []byte(c.ClientSecret)
	}
	meta, err := githubConfigMeta(ctx, src)
	if err != nil {
		return err
	}
	s.cfg.UpdatedBy, s.cfg.UpdatedAt, s.cfg.SecretUpdatedAt = meta.by, meta.at, meta.secretAt
	return nil
}

type configMeta struct {
	by           sql.NullInt64
	at, secretAt time.Time
}

// githubConfigMeta reads updated_by, updated_at and secret_updated_at,
// which older databases may lack.
func githubConfigMeta(ctx context.Context, src *Source) (configMeta, error) {
	col := func(name, expr string) string {
		if src.schema.HasColumn("github_auth_configuration", name) {
			return expr
		}
		return "NULL"
	}
	var m configMeta
	var at, secretAt sql.NullString
	err := src.db.QueryRowContext(ctx, `SELECT `+col("updated_by", "updated_by")+`, `+col("updated_at", "CAST(updated_at AS TEXT)")+`, `+
		col("secret_updated_at", "CAST(secret_updated_at AS TEXT)")+` FROM github_auth_configuration ORDER BY id LIMIT 1`). // #nosec G202 -- constant column choices
		Scan(&m.by, &at, &secretAt)
	if err != nil {
		return configMeta{}, fmt.Errorf("legacy: read GitHub configuration: %w", err)
	}
	if m.at, err = dbTime(at); err == nil {
		m.secretAt, err = dbTime(secretAt)
	}
	if err != nil {
		return configMeta{}, &StepError{Record: "github_auth_configuration", Err: err}
	}
	return m, nil
}

func (s *githubConfigStep) Write(ctx context.Context, tx *store.Tx, seal Sealer) error {
	if !s.found {
		return nil
	}
	return github.ImportConfigTx(ctx, tx, seal, s.cfg)
}

// Verify opens the stored secret and compares it and every other field
// with the legacy row.
func (s *githubConfigStep) Verify(ctx context.Context, tx *store.Tx, open Opener) error {
	got, found, err := github.ImportedConfigTx(ctx, tx, open)
	if err != nil {
		return err
	}
	w := s.cfg
	if found != s.found || found && (got.Enabled != w.Enabled || got.ClientID != w.ClientID || !bytes.Equal(got.ClientSecret, w.ClientSecret) ||
		got.RedirectURI != w.RedirectURI || got.AutoProvision != w.AutoProvision || got.AllowedOrgs != w.AllowedOrgs ||
		got.Generation != w.Generation || got.UpdatedBy != w.UpdatedBy || !got.UpdatedAt.Equal(w.UpdatedAt) ||
		!got.SecretUpdatedAt.Equal(w.SecretUpdatedAt)) {
		return errors.New("legacy: the stored GitHub configuration differs")
	}
	return nil
}

func (s *githubConfigStep) Report() StepReport {
	n := 0
	if s.found {
		n = 1
	}
	return StepReport{Entity: "E06", Version: 1, Read: n, Written: n}
}
