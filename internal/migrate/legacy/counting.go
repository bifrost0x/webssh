package legacy

import (
	"context"
	"fmt"
	"io/fs"
	"slices"
)

// countedTables are the tables the migration counts without importing
// them. Only these names reach the statements below.
var countedTables = []string{
	"webauthn_credentials", "totp_enrollments", "authentication_sessions", "pending_authentications",
	"step_up_grants", "step_up_intents", "factor_bootstrap_tokens", "github_oauth_states", "oidc_login_states",
	"webauthn_challenges", "socket_sessions", "automation_schedules", "oidc_identities", "ldap_identities",
	"github_identities", "github_auth_configuration",
}

// countTable counts the rows of a table; a table the database lacks has
// none, and a table a restore empties counts as empty.
func countTable(ctx context.Context, src *Source, table string) (int, error) {
	if !slices.Contains(countedTables, table) {
		return 0, fmt.Errorf("legacy: %q is not a counted table", table)
	}
	if !src.schema.HasTable(table) || src.emptiedByRestore(table) {
		return 0, nil
	}
	var n int
	if err := src.db.QueryRowContext(ctx, `SELECT count(*) FROM "`+table+`"`).Scan(&n); err != nil { // #nosec G202 -- constant table names
		return 0, fmt.Errorf("legacy: count %s: %w", table, err)
	}
	return n, nil
}

// countPerUser counts the rows of a table per user_id.
func countPerUser(ctx context.Context, src *Source, table string) (map[int64]int, error) {
	out := map[int64]int{}
	if !slices.Contains(countedTables, table) {
		return nil, fmt.Errorf("legacy: %q is not a counted table", table)
	}
	if !src.schema.HasTable(table) || src.emptiedByRestore(table) || !src.schema.HasColumn(table, "user_id") {
		return out, nil
	}
	rows, err := src.db.QueryContext(ctx, `SELECT user_id, count(*) FROM "`+table+`" GROUP BY user_id`) // #nosec G202 -- constant table names
	if err != nil {
		return nil, fmt.Errorf("legacy: count %s: %w", table, err)
	}
	defer rows.Close()
	for rows.Next() {
		var id *int64
		var n int
		if err := rows.Scan(&id, &n); err != nil {
			return nil, fmt.Errorf("legacy: count %s: %w", table, err)
		}
		if id != nil {
			out[*id] = n
		}
	}
	return out, rows.Err()
}

// countRuntimeFiles counts the regular files directly below a runtime
// directory of DATA_DIR (.access-revocations, .ldap-revocation-fences,
// tmp). Runtime paths are not part of the legacy source; a link or an
// unreadable entry there is not counted and does not stop the migration.
func countRuntimeFiles(src *Source, dir string) int {
	entries, err := fs.ReadDir(src.root.FS(), dir)
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		if e.Type().IsRegular() {
			n++
		}
	}
	return n
}
