package settings

import (
	"context"
	"encoding/json/jsontext"
	"fmt"
	"maps"
	"slices"

	"github.com/bifrost0x/webssh/internal/store"
)

// legacyAppSchema is the version of app_settings.json the import reads
// (CURRENT_STORAGE_VERSIONS['app_settings']).
const legacyAppSchema = 2

var legacyAppBooleans = []string{
	"credentials_enabled", "automation_enabled", "automation_effective_observed",
	"automation_enabled_from_environment", "sftp_chmod_enabled", "server_operations_enabled",
	"tmux_enabled", "tmux_default", "support_links_enabled", "tailscale_ssh_restrict_tailnet_routes",
	"ssh_gateway_enabled", "herdr_enabled", "registration_enabled",
}

var legacyAppBounds = map[string][2]int64{
	"login_username_limit":        {1, 1000},
	"login_username_global_limit": {1, 1000},
	"ratelimit_ipv6_prefix":       {48, 128},
	"audit_backup_count":          {1, AuditBackupCountMax},
}

// ImportApp stores the legacy app_settings.json in the migration
// transaction. doc is the document after the Python start-up migrations
// (migrate_runtime_features, migrate_feature_policies) were applied in
// memory. Every key except schema_version is copied verbatim, the opaque
// policy revisions included: schedules and credentials are bound to them.
// Absent keys stay absent, so this release's default applies only where
// D-01 allows it. It returns the stored keys, sorted.
func ImportApp(ctx context.Context, tx *store.Tx, doc jsontext.Value, nowUS int64) ([]string, error) {
	values, err := parseLegacyApp(doc)
	if err != nil {
		return nil, err
	}
	keys := slices.Sorted(maps.Keys(values))
	for _, key := range keys {
		if err := putApp(ctx, tx, key, values[key], SourceMigrated, "", nowUS); err != nil {
			return nil, err
		}
	}
	return keys, nil
}

// VerifyApp checks that every key of the legacy document is stored with
// the same value.
func VerifyApp(ctx context.Context, tx *store.Tx, doc jsontext.Value) error {
	values, err := parseLegacyApp(doc)
	if err != nil {
		return err
	}
	rows, err := readApp(ctx, tx)
	if err != nil {
		return err
	}
	for key, v := range values {
		r, ok := rows[key]
		if !ok || string(r.value) != string(v) {
			return fmt.Errorf("settings: application setting %s differs from the legacy file", key)
		}
	}
	return nil
}

// ImportRecoveryCheck stores the notice of a portable restore
// (recovery-check.json, A07) as the application setting recovery_check.
// The legacy reader treats a malformed or oversized file as absent.
func ImportRecoveryCheck(ctx context.Context, tx *store.Tx, v jsontext.Value, nowUS int64) error {
	c, err := compact(v)
	if err != nil || len(c) > 512 {
		return fmt.Errorf("%w: recovery-check.json", ErrLegacyDocument)
	}
	return putApp(ctx, tx, "recovery_check", c, SourceMigrated, "", nowUS)
}

// parseLegacyApp checks a document like _valid_settings of
// app/app_settings.py.
func parseLegacyApp(doc jsontext.Value) (map[string]jsontext.Value, error) {
	c, err := compact(doc)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrLegacyDocument, err)
	}
	members, ok := asObject(c)
	if !ok {
		return nil, fmt.Errorf("%w: not an object", ErrLegacyDocument)
	}
	out := map[string]jsontext.Value{}
	schemaOK := false
	for _, m := range members {
		if m.name == legacyKeySchemaVersion {
			n, ok := asInt(m.value)
			schemaOK = ok && n == legacyAppSchema
			continue
		}
		if slices.Contains(policyKeys, m.name) || m.name == "recovery_check" {
			return nil, errPolicyKey(m.name)
		}
		if !validLegacyApp(m.name, m.value) || m.name == "" {
			return nil, fmt.Errorf("%w: %s", ErrLegacyDocument, m.name)
		}
		out[m.name] = m.value
	}
	if !schemaOK {
		return nil, fmt.Errorf("%w: schema_version", ErrLegacyDocument)
	}
	return out, nil
}

func validLegacyApp(key string, v jsontext.Value) bool {
	if slices.Contains(legacyAppBooleans, key) {
		_, ok := asBool(v)
		return ok
	}
	if b, ok := legacyAppBounds[key]; ok {
		n, ok := asInt(v)
		return ok && n >= b[0] && n <= b[1]
	}
	switch key {
	case "credentials_enabled_revision", "automation_enabled_revision":
		_, ok := asString(v)
		return ok
	case "runtime_feature_migration":
		items, ok := asArray(v)
		if !ok {
			return false
		}
		for _, item := range items {
			s, ok := asString(item)
			if _, known := RuntimeFeatures[s]; !ok || !known {
				return false
			}
		}
	}
	return true
}
