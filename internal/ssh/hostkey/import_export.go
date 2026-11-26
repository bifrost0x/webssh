package hostkey

import (
	"context"

	"github.com/bifrost0x/webssh/internal/store"
)

// FileTx returns the stored known_hosts file of a scope byte for byte,
// for the migration's verification; found is false when there is none.
func FileTx(ctx context.Context, tx *store.Tx, scope Scope, owner int64) (raw []byte, found bool, err error) {
	f, err := readFile(ctx, tx, scope, owner)
	if err != nil {
		return nil, false, err
	}
	return f.raw, f.present, nil
}
