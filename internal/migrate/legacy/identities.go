package legacy

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// ExternalIdentity links an account to an external sign-in provider.
type ExternalIdentity struct {
	Provider string // "oidc", "ldap" or "github"
	UserID   int64
	Issuer   string // OIDC issuer, LDAP provider name; empty for GitHub
	Subject  string // OIDC subject, LDAP subject, GitHub user id
	Login    string // LDAP directory user name, GitHub login
	// DistinguishedName is the LDAP DN; Provisioned reports a GitHub
	// account created by GitHub sign-in.
	DistinguishedName string
	Provisioned       bool
}

// ExternalIdentities reads oidc_identities, ldap_identities and
// github_identities.
func (s *Source) ExternalIdentities(ctx context.Context) ([]ExternalIdentity, error) {
	var parts []string
	for _, p := range []struct{ table, sel string }{
		{"oidc_identities", `SELECT 'oidc', user_id, issuer, subject, '', '', 0 FROM oidc_identities`},
		{"ldap_identities", `SELECT 'ldap', user_id, provider, subject, directory_username, distinguished_name, 0 FROM ldap_identities`},
		{"github_identities", `SELECT 'github', user_id, '', github_user_id, login, '', provisioned_by_github FROM github_identities`},
	} {
		if s.schema.HasTable(p.table) {
			parts = append(parts, p.sel)
		}
	}
	if len(parts) == 0 {
		return nil, nil
	}
	query := strings.Join(parts, " UNION ALL ") + " ORDER BY 1, 2" // #nosec G202 -- joins the constant statements above
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("legacy: read external identities: %w", err)
	}
	defer rows.Close()
	var out []ExternalIdentity
	for rows.Next() {
		var e ExternalIdentity
		if err := rows.Scan(&e.Provider, &e.UserID, &e.Issuer, &e.Subject, &e.Login, &e.DistinguishedName, &e.Provisioned); err != nil {
			return nil, fmt.Errorf("legacy: read external identities: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// Schedule is one row of automation_schedules. Grant is the stored JSON
// text: the frozen runbook, targets and the vault generation it may use.
type Schedule struct {
	ID         string
	UserID     int64
	Revision   int64
	Enabled    bool
	Cron       string
	Timezone   string
	Grant      string
	NextAt     float64
	LastStatus string
	ClaimID    sql.NullString
}

// Schedules reads automation_schedules.
func (s *Source) Schedules(ctx context.Context) ([]Schedule, error) {
	if !s.schema.HasTable("automation_schedules") {
		return nil, nil
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, user_id, revision, enabled, cron, timezone, CAST("grant" AS TEXT),
		next_at, last_status, claim_id FROM automation_schedules ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("legacy: read schedules: %w", err)
	}
	defer rows.Close()
	var out []Schedule
	for rows.Next() {
		var sc Schedule
		if err := rows.Scan(&sc.ID, &sc.UserID, &sc.Revision, &sc.Enabled, &sc.Cron, &sc.Timezone, &sc.Grant,
			&sc.NextAt, &sc.LastStatus, &sc.ClaimID); err != nil {
			return nil, fmt.Errorf("legacy: read schedules: %w", err)
		}
		out = append(out, sc)
	}
	return out, rows.Err()
}

// SecurityFeatures reads security_feature_states: feature name to enabled.
func (s *Source) SecurityFeatures(ctx context.Context) (map[string]bool, error) {
	if !s.schema.HasTable("security_feature_states") {
		return map[string]bool{}, nil
	}
	rows, err := s.db.QueryContext(ctx, `SELECT feature, enabled FROM security_feature_states`)
	if err != nil {
		return nil, fmt.Errorf("legacy: read security features: %w", err)
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var name string
		var enabled bool
		if err := rows.Scan(&name, &enabled); err != nil {
			return nil, fmt.Errorf("legacy: read security features: %w", err)
		}
		out[name] = enabled
	}
	return out, rows.Err()
}
