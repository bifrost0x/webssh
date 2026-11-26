package legacy

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"maps"

	"github.com/bifrost0x/webssh/internal/operations"
	"github.com/bifrost0x/webssh/internal/store"
)

// featureGatesStep migrates entity E07: the administrator choices of
// security_feature_states, verbatim. Absent rows stay absent, so the
// upgrade defaults of the gates apply as in Python.
type featureGatesStep struct {
	gates []operations.ImportGate
}

func (*featureGatesStep) Entity() string { return "E07" }

func (*featureGatesStep) Version() int { return 1 }

func (s *featureGatesStep) Read(ctx context.Context, src *Source) error {
	if !src.schema.HasTable("security_feature_states") {
		return nil
	}
	rows, err := src.db.QueryContext(ctx, `SELECT feature, enabled, updated_by, CAST(updated_at AS TEXT) FROM security_feature_states ORDER BY feature`)
	if err != nil {
		return fmt.Errorf("legacy: read security features: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var g operations.ImportGate
		var at sql.NullString
		if err := rows.Scan(&g.Feature, &g.Enabled, &g.UpdatedBy, &at); err != nil {
			return fmt.Errorf("legacy: read security features: %w", err)
		}
		if g.UpdatedAt, err = dbTime(at); err != nil {
			return &StepError{Record: g.Feature, Err: err}
		}
		s.gates = append(s.gates, g)
	}
	return rows.Err()
}

func (s *featureGatesStep) Write(ctx context.Context, tx *store.Tx, _ Sealer) error {
	for _, g := range s.gates {
		if err := operations.ImportGateTx(ctx, tx, g); err != nil {
			return &StepError{Record: g.Feature, Err: err}
		}
	}
	return nil
}

func (s *featureGatesStep) Verify(ctx context.Context, tx *store.Tx, _ Opener) error {
	got, err := operations.StoredTx(ctx, tx)
	if err != nil {
		return err
	}
	want := map[string]bool{}
	for _, g := range s.gates {
		want[g.Feature] = g.Enabled
	}
	if !maps.Equal(got, want) {
		return errors.New("legacy: the stored security feature choices differ")
	}
	return nil
}

func (s *featureGatesStep) Report() StepReport {
	return StepReport{Entity: "E07", Version: 1, Read: len(s.gates), Written: len(s.gates)}
}
