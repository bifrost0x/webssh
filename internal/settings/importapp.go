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
// D-01 allows it.
func ImportApp(ctx context.Context, tx *store.Tx, doc jsontext.Value, nowUS int64) (AppImport, error) {
	parsed, err := parseLegacyApp(doc)
	if err != nil {
		return AppImport{}, err
	}
	out := AppImport{Keys: slices.Sorted(maps.Keys(parsed.values)), Skipped: parsed.skipped, LoneSurrogates: parsed.lone}
	for _, key := range out.Keys {
		if err := putApp(ctx, tx, key, parsed.values[key], SourceMigrated, "", nowUS); err != nil {
			return AppImport{}, err
		}
	}
	return out, nil
}

// AppImport is the outcome of importing app_settings.json.
type AppImport struct {
	// Keys are the stored settings, sorted.
	Keys []string
	// Skipped are legacy keys that would shadow a setting of this release
	// (recovery_check, the derived settings); they stay in the legacy file
	// and are listed in the report.
	Skipped []string
	// LoneSurrogates is as in UserImport.
	LoneSurrogates bool
}

// VerifyApp checks that every key of the legacy document is stored with
// the same value.
func VerifyApp(ctx context.Context, tx *store.Tx, doc jsontext.Value) error {
	parsed, err := parseLegacyApp(doc)
	if err != nil {
		return err
	}
	rows, err := readApp(ctx, tx)
	if err != nil {
		return err
	}
	for key, v := range parsed.values {
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
	c, _, err := pythonLoad(v)
	if err != nil || len(c) > 512 {
		return fmt.Errorf("%w: recovery-check.json", ErrLegacyDocument)
	}
	return putApp(ctx, tx, "recovery_check", c, SourceMigrated, "", nowUS)
}

type legacyApp struct {
	values  map[string]jsontext.Value
	skipped []string
	lone    bool
}

// parseLegacyApp reads a document like json.loads (pythonLoad) and checks
// it like _valid_settings of app/app_settings.py. Keys that would shadow a
// setting of this release are skipped, not refused: Python kept them as
// values nobody reads.
func parseLegacyApp(doc jsontext.Value) (legacyApp, error) {
	c, lone, err := pythonLoad(doc)
	if err != nil {
		return legacyApp{}, fmt.Errorf("%w: %v", ErrLegacyDocument, err)
	}
	members, ok := asObject(c)
	if !ok {
		return legacyApp{}, fmt.Errorf("%w: not an object", ErrLegacyDocument)
	}
	out := legacyApp{values: map[string]jsontext.Value{}, lone: lone}
	schemaOK := false
	for _, m := range members {
		if m.name == legacyKeySchemaVersion {
			n, ok := asInt(m.value)
			schemaOK = ok && n == legacyAppSchema
			continue
		}
		if !validLegacyApp(m.name, m.value) {
			return legacyApp{}, fmt.Errorf("%w: %s", ErrLegacyDocument, m.name)
		}
		if slices.Contains(policyKeys, m.name) || m.name == "recovery_check" {
			out.skipped = append(out.skipped, m.name)
			continue
		}
		out.values[m.name] = m.value
	}
	if !schemaOK {
		return legacyApp{}, fmt.Errorf("%w: schema_version", ErrLegacyDocument)
	}
	slices.Sort(out.skipped)
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
