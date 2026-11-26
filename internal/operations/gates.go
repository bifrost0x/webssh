package operations

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/store"
)

// Features are the security feature gates (security_features.FEATURE_NAMES).
var Features = []string{"passkey", "totp", "oidc", "ldap", "recovery"}

var displayNames = map[string]string{
	"passkey": "Passkeys", "totp": "TOTP", "oidc": "OIDC", "ldap": "LDAP", "recovery": "Recovery codes",
}

// upgradeDefaults are the gates that are on without a stored choice when
// the deployment allows them; TOTP needs an explicit administrator choice.
var upgradeDefaults = []string{"passkey", "oidc", "ldap", "recovery"}

var configurationKeys = map[string][]string{
	"passkey":  {"WEBAUTHN_ENABLED", "WEBAUTHN_RP_ID", "WEBAUTHN_ORIGIN"},
	"totp":     {"TOTP_ENABLED"},
	"oidc":     {"OIDC_ENABLED", "OIDC_ISSUER", "OIDC_CLIENT_ID", "OIDC_CLIENT_SECRET_FILE", "OIDC_REDIRECT_URI"},
	"ldap":     {"LDAP_ENABLED", "LDAP_URL", "LDAP_BACKUP_URL", "LDAP_BASE_DN", "LDAP_BIND_DN", "LDAP_BIND_PASSWORD_FILE", "LDAP_CA_FILE", "LDAP_USER_FILTER", "LDAP_UNIQUE_ID_ATTRIBUTE"},
	"recovery": {"RECOVERY_CODES_ENABLED"},
}

const wiki = "https://github.com/bifrost0x/webssh/wiki/"

var documentation = map[string]string{
	"passkey": wiki + "Passkeys-and-Recovery-Codes", "totp": wiki + "Passkeys-and-Recovery-Codes",
	"oidc": wiki + "OpenID-Connect", "ldap": wiki + "LDAP-and-Active-Directory", "recovery": wiki + "Passkeys-and-Recovery-Codes",
}

// Schema stores the administrator choices (entity E07, copied verbatim).
func Schema() store.Schema {
	return store.Schema{Owner: "operations", Migrations: []store.Migration{{Version: 1, SQL: `
CREATE TABLE operations_feature_gates (
	feature    TEXT PRIMARY KEY CHECK (feature IN ('passkey', 'totp', 'oidc', 'ldap', 'recovery')),
	enabled    INTEGER NOT NULL CHECK (enabled IN (0, 1)),
	updated_by INTEGER,
	updated_us INTEGER
) STRICT;`}}}
}

// Readiness is the start-up result of a feature: whether its code and
// configuration can serve it, and why not.
type Readiness struct {
	Ready  bool
	Reason string
}

// Status is the effective state of one gate (FeatureStatus).
type Status struct {
	Name              string   `json:"name"`
	DeploymentAllowed bool     `json:"deployment_allowed"`
	Ready             bool     `json:"ready"`
	AdminEnabled      bool     `json:"admin_enabled"`
	Active            bool     `json:"active"`
	Reason            *string  `json:"reason"`
	ConfigurationKeys []string `json:"configuration_keys"`
	DocumentationURL  string   `json:"documentation_url"`
}

// Auditor writes security events (provided by internal/audit).
type Auditor interface {
	Security(event string, kv ...any)
}

// Gates combines the deployment ceiling (WEBAUTHN_ENABLED, TOTP_ENABLED,
// OIDC_ENABLED, LDAP_ENABLED, RECOVERY_CODES_ENABLED), the start-up
// readiness and the administrator choice. A feature is active only when
// all three allow it (fail closed).
type Gates struct {
	DB *store.DB
	// Deployment holds the environment flag of each feature.
	Deployment map[string]bool
	// Ready holds the readiness of each feature; a missing entry is not
	// ready.
	Ready map[string]Readiness
	Audit Auditor
	Now   func() time.Time
}

var errUnknown = fault.New(fault.NotFound, "")

// normalize is _normalize_name: trimmed, lower case, in the registry.
func normalize(name string) (string, error) {
	n := strings.ToLower(strings.TrimSpace(name))
	if !slices.Contains(Features, n) {
		return "", errUnknown
	}
	return n, nil
}

func (g *Gates) stored(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, name string) (enabled, found bool, err error) {
	err = q.QueryRowContext(ctx, `SELECT enabled FROM operations_feature_gates WHERE feature = ?`, name).Scan(&enabled)
	if errors.Is(err, sql.ErrNoRows) {
		return false, false, nil
	}
	return enabled, err == nil, err
}

func (g *Gates) status(name string, enabled, found bool) Status {
	deploy := g.Deployment[name]
	ready := g.Ready[name]
	admin := enabled
	if !found {
		admin = deploy && slices.Contains(upgradeDefaults, name)
	}
	s := Status{Name: name, DeploymentAllowed: deploy, Ready: ready.Ready, AdminEnabled: admin,
		Active: deploy && ready.Ready && admin, ConfigurationKeys: configurationKeys[name], DocumentationURL: documentation[name]}
	var reason string
	switch {
	case !deploy:
		reason = displayNames[name] + " is disabled by deployment configuration."
	case !ready.Ready:
		reason = ready.Reason
		if reason == "" {
			reason = displayNames[name] + " is not ready."
		}
	case !admin:
		reason = displayNames[name] + " is not activated in the admin panel."
	}
	if reason != "" {
		s.Reason = &reason
	}
	return s
}

// Status returns the effective state of one feature.
func (g *Gates) Status(ctx context.Context, name string) (Status, error) {
	n, err := normalize(name)
	if err != nil {
		return Status{}, err
	}
	var s Status
	err = g.DB.Read(ctx, func(tx *store.Tx) error {
		enabled, found, err := g.stored(ctx, tx, n)
		s = g.status(n, enabled, found)
		return err
	})
	if err != nil {
		return Status{}, fault.Wrap(fault.StorageError, err, "")
	}
	return s, nil
}

// All returns every feature in registry order.
func (g *Gates) All(ctx context.Context) ([]Status, error) {
	out := make([]Status, 0, len(Features))
	for _, n := range Features {
		s, err := g.Status(ctx, n)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

// Active implements the gate check of the sign-in and factor packages.
// An unknown feature or a storage failure is inactive.
func (g *Gates) Active(ctx context.Context, name string) (bool, error) {
	s, err := g.Status(ctx, name)
	if err != nil {
		return false, err
	}
	return s.Active, nil
}

// errUnavailable carries the status the page shows beside the refusal.
type errUnavailable struct{ status Status }

func (e errUnavailable) Error() string { return "operations: feature unavailable" }

// set stores the administrator choice (set_feature_active). Enabling a
// feature the deployment or its readiness does not allow is refused.
func (g *Gates) set(ctx context.Context, p principal.Principal, name string, enabled bool) (Status, error) {
	var s Status
	err := g.DB.Write(ctx, func(tx *store.Tx) error {
		was, found, err := g.stored(ctx, tx, name)
		if err != nil {
			return err
		}
		cur := g.status(name, was, found)
		if enabled && (!cur.DeploymentAllowed || !cur.Ready) {
			return errUnavailable{cur}
		}
		now := time.Now
		if g.Now != nil {
			now = g.Now
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO operations_feature_gates (feature, enabled, updated_by, updated_us) VALUES (?, ?, ?, ?)
			ON CONFLICT (feature) DO UPDATE SET enabled = excluded.enabled, updated_by = excluded.updated_by, updated_us = excluded.updated_us`,
			name, enabled, p.UserID, now().UnixMicro()); err != nil {
			return fmt.Errorf("operations: store gate: %w", err)
		}
		s = g.status(name, enabled, true)
		return nil
	})
	if err != nil {
		return Status{}, err
	}
	if g.Audit != nil {
		g.Audit.Security("SECURITY_FEATURE_CHANGED", "admin", p.Username, "feature", name, "enabled", enabled, "active", s.Active)
	}
	return s, nil
}
