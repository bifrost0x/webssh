package legacy

import (
	"fmt"
	"slices"
	"strings"
)

// knownColumns are the columns of the tables the migration reads, as the
// Python release 3.3.x defines them (app/models.py,
// app/automation_schedule.py). A column outside this set may be user data
// of a newer release: STOP (migration specification, section 5.2 step 3).
//
// Older releases lack whole tables (v1.0.0 has only users, socket_sessions
// and ssh_sessions; TOTP, LDAP and security features arrive in v2.0.0,
// GitHub sign-in in v2.4.0, schedules in v3.1.0); Python creates them empty
// with create_all, so a missing table reads as empty. Missing columns are
// filled only where Python adds them with ALTER TABLE (userColumnDefaults);
// in every other table the column set has not changed since the table was
// introduced, so a missing column there is a damaged database.
var knownColumns = map[string][]string{
	"users": {"id", "username", "password_hash", "created_at", "last_login", "is_admin", "is_locked",
		"auth_generation", "mfa_enabled", "settings_default_generation", "mfa_failed_attempts",
		"mfa_last_failed_at", "mfa_step_up_failed_attempts", "mfa_step_up_last_failed_at"},
	"totp_authenticators":       {"id", "user_id", "encrypted_secret", "label", "active", "last_accepted_step", "created_at", "activated_at", "last_used_at"},
	"totp_enrollments":          {"id", "token_hash", "user_id", "session_binding_hash", "encrypted_secret", "label", "created_at", "expires_at"},
	"recovery_codes":            {"id", "user_id", "code_hash", "created_at"},
	"webauthn_credentials":      {"id", "user_id", "credential_id", "public_key", "sign_count", "transports", "name", "created_at", "last_used_at"},
	"github_auth_configuration": {"id", "enabled", "client_id", "encrypted_client_secret", "redirect_uri", "auto_provision", "allowed_orgs_json", "generation", "updated_by", "updated_at", "secret_updated_at"},
	"github_identities":         {"id", "user_id", "github_user_id", "login", "display_name", "provisioned_by_github", "created_at", "updated_at", "last_verified_at"},
	"oidc_identities":           {"id", "user_id", "issuer", "subject", "created_at"},
	"ldap_identities":           {"id", "user_id", "provider", "subject", "directory_username", "distinguished_name", "created_at", "last_verified_at"},
	"security_feature_states":   {"feature", "enabled", "updated_by", "updated_at"},
	"automation_schedules":      {"id", "user_id", "revision", "enabled", "cron", "timezone", "grant", "next_at", "last_status", "claim_id", "claimed_at"},
}

// userColumnDefaults are the users columns that app/models.py
// ensure_user_columns adds to an older database, with the value the ALTER
// TABLE statement gives existing rows. is_admin is special: Python makes
// only the account with the lowest id an administrator (users.go).
var userColumnDefaults = map[string]string{
	"is_admin": "0", "is_locked": "0", "auth_generation": "0", "mfa_enabled": "0",
	"settings_default_generation": "0", "mfa_failed_attempts": "0", "mfa_last_failed_at": "NULL",
	"mfa_step_up_failed_attempts": "0", "mfa_step_up_last_failed_at": "NULL",
}

// checkKnownColumns rejects unknown columns in the tables the migration
// reads and missing columns that Python would not add.
func (sc Schema) checkKnownColumns() error {
	for table, known := range knownColumns {
		cols, ok := sc.Tables[table]
		if !ok {
			continue
		}
		for _, c := range cols {
			if !slices.Contains(known, c) {
				return fmt.Errorf("legacy: table %q has column %q, which this release does not know", table, c)
			}
		}
		for _, c := range known {
			if slices.Contains(cols, c) {
				continue
			}
			if _, fill := userColumnDefaults[c]; table == "users" && fill {
				continue
			}
			return fmt.Errorf("legacy: table %q lacks column %q", table, c)
		}
	}
	return nil
}

// MissingUserColumns lists the users columns filled with Python's
// defaults, for the migration report.
func (sc Schema) MissingUserColumns() []string {
	var out []string
	for _, c := range knownColumns["users"] {
		if !sc.HasColumn("users", c) {
			out = append(out, c)
		}
	}
	return out
}

// userSelect returns the select list for users, with Python's default for
// each missing column.
func (sc Schema) userSelect(columns ...string) string {
	exprs := make([]string, len(columns))
	for i, c := range columns {
		switch {
		case sc.HasColumn("users", c) && c == "created_at":
			exprs[i] = `CAST(created_at AS TEXT)`
		case sc.HasColumn("users", c):
			exprs[i] = `"` + c + `"`
		default:
			exprs[i] = userColumnDefaults[c] // checkKnownColumns guarantees a default
		}
	}
	return strings.Join(exprs, ", ")
}
