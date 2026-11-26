package operations

import (
	"context"
	"database/sql"
	"fmt"
	"slices"
	"time"

	"github.com/bifrost0x/webssh/internal/store"
)

// ImportGate is one administrator choice of the Python release
// (security_feature_states, entity E07).
type ImportGate struct {
	Feature   string
	Enabled   bool
	UpdatedBy sql.NullInt64
	UpdatedAt time.Time // zero when unknown
}

// ImportGateTx stores a migrated choice verbatim, inside the migration's
// transaction. A feature name this release does not know is refused, as
// the Python registry would refuse it.
func ImportGateTx(ctx context.Context, tx *store.Tx, g ImportGate) error {
	if !slices.Contains(Features, g.Feature) {
		return fmt.Errorf("operations: import: unknown security feature %q", g.Feature)
	}
	var by, at any
	if g.UpdatedBy.Valid {
		by = g.UpdatedBy.Int64
	}
	if !g.UpdatedAt.IsZero() {
		at = g.UpdatedAt.UnixMicro()
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO operations_feature_gates (feature, enabled, updated_by, updated_us) VALUES (?, ?, ?, ?)`,
		g.Feature, g.Enabled, by, at); err != nil {
		return fmt.Errorf("operations: import gate %s: %w", g.Feature, err)
	}
	return nil
}

// StoredTx returns the stored administrator choice of every feature
// that has one, for the migration's verification.
func StoredTx(ctx context.Context, tx *store.Tx) (map[string]bool, error) {
	rows, err := tx.QueryContext(ctx, `SELECT feature, enabled FROM operations_feature_gates`)
	if err != nil {
		return nil, fmt.Errorf("operations: read gates: %w", err)
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var name string
		var on bool
		if err := rows.Scan(&name, &on); err != nil {
			return nil, fmt.Errorf("operations: read gates: %w", err)
		}
		out[name] = on
	}
	return out, rows.Err()
}
