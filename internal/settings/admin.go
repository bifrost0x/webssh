package settings

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json/jsontext"
	"errors"
	"slices"

	"github.com/bifrost0x/webssh/internal/store"
)

// The administrator settings of POST /admin/api/settings
// (update_admin_settings of app/app_settings.py). Every accepted value of
// one request is written in one transaction, so a rejected combination or
// a failed write leaves every setting as it was, and the previous values
// the audit compares with are read in the same transaction.

// SignInBound is the accepted range of a sign-in protection value.
type SignInBound struct{ Min, Max int }

// SignInBounds are SIGN_IN_PROTECTION_BOUNDS, in their order.
var SignInBounds = []struct {
	Name string
	SignInBound
}{
	{"login_username_limit", SignInBound{1, 1000}},
	{"login_username_global_limit", SignInBound{1, 1000}},
	{"ratelimit_ipv6_prefix", SignInBound{48, 128}},
}

var signInDefaults = map[string]int64{
	"login_username_limit":        DefaultLoginUsernameLimit,
	"login_username_global_limit": DefaultLoginUsernameGlobalLimit,
	"ratelimit_ipv6_prefix":       DefaultRateLimitIPv6Prefix,
}

// Role permissions of the administration (D-18, D-29): the boolean the
// page shows is whether the role "user" holds the permission; an
// administrator always does. They have no Python counterpart.
const (
	SettingDiscoveryUsers    = "host_discovery_users"
	SettingReachabilityUsers = "host_reachability_users"
)

var rolePermissions = map[string]string{
	SettingDiscoveryUsers:    PolicyDiscovery,
	SettingReachabilityUsers: PolicyReachability,
}

// featurePolicies are the switches with a revision that prepared
// background work is bound to.
var featurePolicies = []string{"credentials_enabled", "automation_enabled"}

// AdminSettingNames are the settings an administrator can change, in the
// order the Python release applies and audits them.
func AdminSettingNames() []string {
	names := []string{"registration_enabled", "ssh_gateway_enabled", "herdr_enabled",
		"support_links_enabled", "tailscale_ssh_restrict_tailnet_routes"}
	for _, b := range SignInBounds {
		names = append(names, b.Name)
	}
	names = append(names, featurePolicies...)
	names = append(names, runtimeFeatureOrder...)
	return append(names, SettingDiscoveryUsers, SettingReachabilityUsers)
}

// runtimeFeatureOrder is the order of RUNTIME_FEATURES.
var runtimeFeatureOrder = []string{"sftp_chmod_enabled", "server_operations_enabled", "tmux_enabled", "tmux_default"}

// AdminChange is the stored value of one setting before and after an
// update; nil stands for "nothing stored".
type AdminChange struct {
	Previous, Current any
}

// ErrGlobalBelowSource rejects a username limit across all sources below
// the per-source limit; Setting names the limit the request changed.
type ErrGlobalBelowSource struct{ Setting string }

const globalBelowSourceMessage = "login_username_global_limit must not be lower than login_username_limit"

func (e ErrGlobalBelowSource) Error() string { return globalBelowSourceMessage }

// UpdateAdmin applies type-checked changes (bool, or int for the
// sign-in protection) and returns the stored values before and after.
// The caller has checked the types, ranges and locks; an unknown name is
// refused.
func (s *Service) UpdateAdmin(ctx context.Context, changes map[string]any) (map[string]AdminChange, error) {
	now := s.now().UnixMicro()
	out := map[string]AdminChange{}
	err := s.db.Write(ctx, func(tx *store.Tx) error {
		rows, err := readApp(ctx, tx)
		if err != nil {
			return err
		}
		put := func(key string, v jsontext.Value) error {
			rows[key] = appRow{value: v, source: SourceAdmin}
			return putApp(ctx, tx, key, v, SourceAdmin, "", now)
		}
		previous := map[string]any{}
		for name := range changes {
			previous[name] = storedAdmin(rows, name)
		}
		for _, name := range AdminSettingNames() {
			v, ok := changes[name]
			if !ok {
				continue
			}
			if err := s.applyAdmin(rows, put, name, v); err != nil {
				return err
			}
		}
		for name := range changes {
			if !slices.Contains(AdminSettingNames(), name) {
				return invalid(name + " is not an admin setting")
			}
		}
		for _, name := range []string{"login_username_global_limit", "login_username_limit"} {
			if _, ok := changes[name]; ok && globalBelowSource(rows) {
				return ErrGlobalBelowSource{Setting: name}
			}
		}
		for name := range changes {
			out[name] = AdminChange{Previous: previous[name], Current: storedAdmin(rows, name)}
		}
		return nil
	})
	if errors.As(err, new(ErrGlobalBelowSource)) {
		return nil, err
	}
	if err != nil {
		return nil, storageFault(err)
	}
	return out, nil
}

func (s *Service) applyAdmin(rows map[string]appRow, put func(string, jsontext.Value) error, name string, v any) error {
	switch {
	case slices.Contains(featurePolicies, name):
		b, _ := v.(bool)
		if cur, ok := rows[name]; ok && isBoolValue(cur.value, b) {
			return nil
		}
		if err := put(name, marshalValue(b)); err != nil {
			return err
		}
		// Changing away and back must revoke old background grants too.
		if err := put(name+"_revision", marshalValue(newRevision())); err != nil {
			return err
		}
		if name == "automation_enabled" {
			effective := b
			if s.env.Explicit["AUTOMATION_ENABLED"] {
				effective = s.env.Values["AUTOMATION_ENABLED"]
			}
			if err := put("automation_effective_observed", marshalValue(effective)); err != nil {
				return err
			}
			return put("automation_enabled_from_environment", marshalValue(false))
		}
		return nil
	case slices.Contains(runtimeFeatureOrder, name):
		if err := put(name, marshalValue(v)); err != nil {
			return err
		}
		var kept []string
		if r, ok := rows["runtime_feature_migration"]; ok {
			items, _ := asArray(r.value)
			for _, item := range items {
				if s, ok := asString(item); ok && s != name {
					kept = append(kept, s)
				}
			}
		}
		if kept == nil {
			kept = []string{}
		}
		return put("runtime_feature_migration", marshalValue(kept))
	case rolePermissions[name] != "":
		b, _ := v.(bool)
		return put(rolePermissions[name], rolesWith(rows, rolePermissions[name], RoleUser, b))
	default:
		return put(name, marshalValue(v))
	}
}

// rolesWith returns the role object of key with role set to granted,
// keeping every other role as stored.
func rolesWith(rows map[string]appRow, key, role string, granted bool) jsontext.Value {
	roles := map[string]bool{}
	if r, ok := rows[key]; ok {
		members, _ := asObject(r.value)
		for _, m := range members {
			if b, ok := asBool(m.value); ok {
				roles[m.name] = b
			}
		}
	}
	roles[role] = granted
	return marshalValue(roles)
}

func isBoolValue(v jsontext.Value, b bool) bool {
	got, ok := asBool(v)
	return ok && got == b
}

// storedAdmin is _stored_value: the sign-in values fall back to their
// defaults, the tailnet restriction is on unless false is stored, a role
// permission is whether the role user holds it, anything else is the
// stored boolean or nil.
func storedAdmin(rows map[string]appRow, name string) any {
	if def, ok := signInDefaults[name]; ok {
		if r, ok := rows[name]; ok {
			if n, ok := asInt(r.value); ok {
				return n
			}
		}
		return def
	}
	if key := rolePermissions[name]; key != "" {
		return slices.Contains(policyOf(rows).rolesOf(key), RoleUser)
	}
	r, ok := rows[name]
	if name == "tailscale_ssh_restrict_tailnet_routes" {
		return !ok || !isBoolValue(r.value, false)
	}
	if !ok {
		return nil
	}
	if b, ok := asBool(r.value); ok {
		return b
	}
	return nil
}

func (p Policy) rolesOf(key string) []string {
	if key == PolicyDiscovery {
		return p.Discovery
	}
	return p.Reachability
}

func globalBelowSource(rows map[string]appRow) bool {
	global, _ := storedAdmin(rows, "login_username_global_limit").(int64)
	source, _ := storedAdmin(rows, "login_username_limit").(int64)
	return global < source
}

// newRevision is secrets.token_hex(32).
func newRevision() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b) // crypto/rand.Read never fails
	return hex.EncodeToString(b)
}

// SetAuditBackupCount stores the administrator's audit retention
// (audit_backup_count, 1 to AuditBackupCountMax).
func (s *Service) SetAuditBackupCount(ctx context.Context, n int) error {
	if n < 1 || n > AuditBackupCountMax {
		return invalid("backup_count must be an integer between 1 and 90")
	}
	return s.setApp(ctx, map[string]jsontext.Value{"audit_backup_count": marshalValue(n)})
}
