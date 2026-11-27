package settings

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json/jsontext"
	"fmt"

	"github.com/bifrost0x/webssh/internal/store"
)

// Source says where an application setting came from.
type Source string

// Sources of application settings.
const (
	SourceAdmin        Source = "admin"        // changed through this release
	SourceMigrated     Source = "migrated"     // copied from app_settings.json
	SourceMaterialised Source = "materialised" // derived from the legacy behaviour (D-01)
)

// Environment is what the application settings fall back to or are
// locked by: the boolean environment variables by name (only those that
// are set matter), which of them were set explicitly
// (EXPLICIT_ENVIRONMENT_KEYS), the deployment profile and
// AUDIT_LOG_BACKUP_COUNT. The composition root fills it from
// internal/config.
type Environment struct {
	Values           map[string]bool
	Explicit         map[string]bool
	Production       bool
	AuditBackupCount int
}

// Sign-in protection defaults and bounds (app/app_settings.py).
const (
	DefaultLoginUsernameLimit       = 10
	DefaultLoginUsernameGlobalLimit = 100
	DefaultRateLimitIPv6Prefix      = 128
	AuditBackupCountMax             = 90
)

// SignInProtection are the effective username limits per minute and the
// IPv6 prefix that shares one source bucket.
type SignInProtection struct {
	UsernameLimit       int
	UsernameGlobalLimit int
	IPv6Prefix          int
}

// FeatureStatus is the effective state of a runtime feature switch.
type FeatureStatus struct {
	Enabled bool
	// Source is "compose" (locked by an explicit environment value),
	// "admin" (a stored choice) or "default".
	Source         string
	Locked         bool
	EnvironmentKey string
	// Saved is the stored choice, nil without one.
	Saved    *bool
	Migrated bool
}

// RuntimeFeatures maps the runtime feature settings to their environment
// variables.
var RuntimeFeatures = map[string]string{
	"sftp_chmod_enabled":        "SFTP_CHMOD_ENABLED",
	"server_operations_enabled": "SERVER_OPERATIONS_ENABLED",
	"tmux_enabled":              "TMUX_ENABLED",
	"tmux_default":              "TMUX_DEFAULT",
}

// App is a snapshot of the effective application settings this release
// acts on. Every other stored key is kept but not interpreted.
type App struct {
	RegistrationEnabled bool
	SupportLinksEnabled bool
	SSHGatewayEnabled   bool
	HerdrEnabled        bool
	CredentialsEnabled  bool
	// CredentialsRevision changes whenever an administrator turns saved
	// passwords on or off (credentials_enabled_revision); prepared
	// password operations are bound to it.
	CredentialsRevision    string
	AutomationEnabled      bool
	TailnetRouteRestricted bool
	AuditBackupCount       int
	SignIn                 SignInProtection
	Policy                 Policy

	rows map[string]appRow
	env  Environment
}

type appRow struct {
	value  jsontext.Value
	source Source
	rule   string
}

// App returns the effective application settings.
func (s *Service) App(ctx context.Context) (App, error) {
	var rows map[string]appRow
	err := s.db.Read(ctx, func(tx *store.Tx) error {
		var err error
		rows, err = readApp(ctx, tx)
		return err
	})
	if err != nil {
		return App{}, storageFault(err)
	}
	return effectiveApp(rows, s.env), nil
}

func effectiveApp(rows map[string]appRow, env Environment) App {
	a := App{rows: rows, env: env}
	boolean := func(key string) (value, ok bool) {
		r, found := rows[key]
		if !found {
			return false, false
		}
		return asBool(r.value)
	}
	isTrue := func(key string) bool { v, ok := boolean(key); return ok && v }
	isFalse := func(key string) bool { v, ok := boolean(key); return ok && !v }
	integer := func(key string, def int) int {
		if r, ok := rows[key]; ok {
			if n, ok := asInt(r.value); ok {
				return int(n)
			}
		}
		return def
	}
	// A saved administrator choice wins over REGISTRATION_ENABLED, which
	// was always only the initial value; production never registers.
	switch v, ok := boolean("registration_enabled"); {
	case env.Production:
	case ok:
		a.RegistrationEnabled = v
	default:
		a.RegistrationEnabled = env.Values["REGISTRATION_ENABLED"]
	}
	a.SupportLinksEnabled = !isFalse("support_links_enabled")
	a.SSHGatewayEnabled = isTrue("ssh_gateway_enabled")
	a.HerdrEnabled = isTrue("herdr_enabled")
	a.CredentialsEnabled = isTrue("credentials_enabled")
	if r, ok := rows["credentials_enabled_revision"]; ok {
		a.CredentialsRevision, _ = asString(r.value)
	}
	if env.Explicit["AUTOMATION_ENABLED"] {
		a.AutomationEnabled = env.Values["AUTOMATION_ENABLED"]
	} else {
		a.AutomationEnabled = isTrue("automation_enabled")
	}
	a.TailnetRouteRestricted = !isFalse("tailscale_ssh_restrict_tailnet_routes")
	a.AuditBackupCount = integer("audit_backup_count", env.AuditBackupCount)
	a.SignIn = SignInProtection{
		UsernameLimit:       integer("login_username_limit", DefaultLoginUsernameLimit),
		UsernameGlobalLimit: integer("login_username_global_limit", DefaultLoginUsernameGlobalLimit),
		IPv6Prefix:          integer("ratelimit_ipv6_prefix", DefaultRateLimitIPv6Prefix),
	}
	a.Policy = policyOf(rows)
	return a
}

// RuntimeFeature returns the state of one runtime feature switch
// (runtime_feature_status of the Python release). An unknown name is
// reported disabled.
func (a App) RuntimeFeature(name string) FeatureStatus {
	key, known := RuntimeFeatures[name]
	if !known {
		return FeatureStatus{Source: "default"}
	}
	st := FeatureStatus{EnvironmentKey: key, Locked: a.env.Explicit[key]}
	if r, ok := a.rows[name]; ok {
		if v, ok := asBool(r.value); ok {
			st.Saved = &v
		}
	}
	switch {
	case st.Locked:
		st.Enabled, st.Source = a.env.Values[key], "compose"
	case st.Saved != nil:
		st.Enabled, st.Source = *st.Saved, "admin"
	default:
		st.Enabled, st.Source = a.env.Values[key], "default"
	}
	if r, ok := a.rows["runtime_feature_migration"]; ok {
		if items, ok := asArray(r.value); ok {
			for _, item := range items {
				if s, _ := asString(item); s == name {
					st.Migrated = true
				}
			}
		}
	}
	return st
}

// SetRegistrationEnabled stores the administrator's registration choice.
// The production profile never opens registration.
func (s *Service) SetRegistrationEnabled(ctx context.Context, enabled bool) error {
	if enabled && s.env.Production {
		return invalid("Registration cannot be enabled in the production profile.")
	}
	return s.setApp(ctx, map[string]jsontext.Value{"registration_enabled": marshalValue(enabled)})
}

// SetAutomationEnabled stores the automation switch with a new revision,
// as set_automation_enabled did; AUTOMATION_ENABLED still wins over it.
func (s *Service) SetAutomationEnabled(ctx context.Context, enabled bool) error {
	return s.setApp(ctx, map[string]jsontext.Value{
		"automation_enabled":          marshalValue(enabled),
		"automation_enabled_revision": marshalValue(newRevision()),
	})
}

// SetLoginUsernameLimits stores both username limits per minute; the
// limit across all sources must not be below the per-source limit.
func (s *Service) SetLoginUsernameLimits(ctx context.Context, perUsername, global int) error {
	if perUsername < 1 || perUsername > 1000 || global < 1 || global > 1000 || global < perUsername {
		return invalid("login_username_global_limit must not be lower than login_username_limit")
	}
	return s.setApp(ctx, map[string]jsontext.Value{
		"login_username_limit":        marshalValue(perUsername),
		"login_username_global_limit": marshalValue(global),
	})
}

func (s *Service) setApp(ctx context.Context, values map[string]jsontext.Value) error {
	now := s.now().UnixMicro()
	return storageFault(s.db.Write(ctx, func(tx *store.Tx) error {
		for key, v := range values {
			if err := putApp(ctx, tx, key, v, SourceAdmin, "", now); err != nil {
				return err
			}
		}
		return nil
	}))
}

func readApp(ctx context.Context, tx *store.Tx) (map[string]appRow, error) {
	rows, err := tx.QueryContext(ctx, `SELECT key, value, source, rule FROM settings_app`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]appRow{}
	for rows.Next() {
		var key, value, source, rule string
		if err := rows.Scan(&key, &value, &source, &rule); err != nil {
			return nil, err
		}
		v := jsontext.Value(value)
		if !v.IsValid() {
			return nil, fmt.Errorf("%w: %s", errCorrupt, key)
		}
		out[key] = appRow{value: v, source: Source(source), rule: rule}
	}
	return out, rows.Err()
}

func putApp(ctx context.Context, tx *store.Tx, key string, v jsontext.Value, source Source, rule string, nowUS int64) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO settings_app (key, value, source, rule, updated_us) VALUES (?, ?, ?, ?, ?)
ON CONFLICT (key) DO UPDATE SET value = excluded.value, source = excluded.source, rule = excluded.rule, updated_us = excluded.updated_us`,
		key, string(v), string(source), rule, nowUS)
	return err
}

// newRevision is secrets.token_hex(32).
func newRevision() string {
	var b [32]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
