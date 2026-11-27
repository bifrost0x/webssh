package main

import (
	"context"
	"io"

	"github.com/bifrost0x/webssh/internal/admincli"
	"github.com/bifrost0x/webssh/internal/hosts"
)

func runConnectionStore(ctx context.Context, args []string, s streams) int {
	return connectionStore(ctx, "webssh", args, s)
}

// connectionStore is `connection-store list|delete` (C-BAK-09). It works
// on the Go database; a running server only sees the change at its next
// read, which it does for every request.
func connectionStore(ctx context.Context, prog string, args []string, s streams) int {
	return admincli.ConnectionStore(ctx, prog, args, cliIO(s), openStores(s.stderr))
}

func openStores(stderr io.Writer) admincli.StoreOpener {
	return func(ctx context.Context) (*admincli.StoreAdmin, func() error, error) {
		g, err := openCommandData(ctx, stderr)
		if err != nil {
			return nil, nil, err
		}
		lim := hosts.RecoveryLimits{MaxBytes: g.cfg.Stores.ConnectionStoreRecoveryMaxBytes,
			MaxRecords: g.cfg.Stores.ConnectionStoreRecoveryMaxRecords}
		svc := &hosts.Service{DB: g.db, Limits: hostLimits(g.cfg)}
		return &admincli.StoreAdmin{Accounts: g.accounts, Stores: svc, Limits: lim, Audit: g.audit}, g.Close, nil
	}
}
