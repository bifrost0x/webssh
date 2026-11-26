package settings

import (
	"context"
	"encoding/json/jsontext"
	"fmt"

	"github.com/bifrost0x/webssh/internal/store"
)

// VerifyRecoveryCheck checks that the notice of a portable restore (A07)
// is stored as the legacy reader read it.
func VerifyRecoveryCheck(ctx context.Context, tx *store.Tx, v jsontext.Value) error {
	want, _, err := pythonLoad(v)
	if err != nil {
		return fmt.Errorf("%w: recovery-check.json", ErrLegacyDocument)
	}
	rows, err := readApp(ctx, tx)
	if err != nil {
		return err
	}
	if r, ok := rows["recovery_check"]; !ok || string(r.value) != string(want) || r.source != SourceMigrated {
		return fmt.Errorf("settings: recovery_check differs from recovery-check.json")
	}
	return nil
}
