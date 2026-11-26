package legacy

import (
	"context"
	"os"
	"path/filepath"
)

// m1Pending is an entity M1 leaves in the legacy data
// (KEEP-IN-PLACE) for the phase that migrates it.
type m1Pending struct {
	entity, phase string
	count         func(ctx context.Context, src *Source) (int, error)
}

func pendingEntities(backupTempDir string) []m1Pending {
	return []m1Pending{
		{"E03", "B2", identityCount("ldap")},
		{"E04", "B2", identityCount("github")},
		{"E05", "B2", identityCount("oidc")},
		{"E06", "B2", func(ctx context.Context, src *Source) (int, error) {
			return countTable(ctx, src, "github_auth_configuration")
		}},
		{"E15", "B6", func(ctx context.Context, src *Source) (int, error) {
			return countTable(ctx, src, "automation_schedules")
		}},
		{"E22", "B4", storeItems("smb_shares")},
		{"E26", "B5", storeItems("commands")},
		{"E27", "B5", storeItems("command_sets")},
		{"E29", "B6", storeItems("automation")},
		{"E30", "B6", storeFiles("automation_vault")},
		{"E31", "B6", storeItems("automation_runs")},
		{"E32", "B6", storeItems("credentials")},
		{"E37", "B2", func(_ context.Context, src *Source) (int, error) {
			return countRuntimeFiles(src, ".ldap-revocation-fences"), nil
		}},
		{"E39", "B7", func(_ context.Context, src *Source) (int, error) { return backupOperations(backupTempDir, src) }},
		{"A10", "B7", func(_ context.Context, src *Source) (int, error) { return restoreStatusFiles(backupTempDir, src) }},
	}
}

func identityCount(provider string) func(context.Context, *Source) (int, error) {
	return func(ctx context.Context, src *Source) (int, error) {
		ids, err := src.ExternalIdentities(ctx)
		n := 0
		for _, e := range ids {
			if e.Provider == provider {
				n++
			}
		}
		return n, err
	}
}

// storeItems counts the records of one per-user store over all accounts.
// A store Python cannot read stops the migration, as it would show the
// store as damaged.
func storeItems(store string) func(context.Context, *Source) (int, error) {
	return func(ctx context.Context, src *Source) (int, error) {
		rows, err := src.AccountRows(ctx)
		if err != nil {
			return 0, err
		}
		n := 0
		for _, a := range rows {
			doc, found, err := userStore(src, a.ID, store)
			if err != nil {
				return 0, err
			}
			if found {
				n += doc.records(storeListKey(store))
			}
		}
		return n, nil
	}
}

// storeListKey is the list key of the per-user store named store.
func storeListKey(store string) string {
	for _, spec := range userStores {
		if spec.name == store {
			return spec.listKey
		}
	}
	return ""
}

// storeFiles counts the accounts that have the store.
func storeFiles(store string) func(context.Context, *Source) (int, error) {
	return func(ctx context.Context, src *Source) (int, error) {
		rows, err := src.AccountRows(ctx)
		if err != nil {
			return 0, err
		}
		n := 0
		for _, a := range rows {
			_, found, err := userStore(src, a.ID, store)
			if err != nil {
				return 0, err
			}
			if found {
				n++
			}
		}
		return n, nil
	}
}

// backupOperations counts the entries of this installation's namespace
// below BACKUP_TEMP_DIR (operations, snapshots, restore leftovers).
func backupOperations(backupTempDir string, src *Source) (int, error) {
	ns, ok := backupNamespace(backupTempDir, src)
	if !ok {
		return 0, nil
	}
	entries, err := os.ReadDir(ns)
	if err != nil {
		return 0, nil //nolint:nilerr // a missing or unreadable namespace holds nothing to count
	}
	return len(entries), nil
}

// restoreStatusFiles is 1 when the namespace holds a restore status file.
// An unfinished restore has already stopped the migration (A10).
func restoreStatusFiles(backupTempDir string, src *Source) (int, error) {
	ns, ok := backupNamespace(backupTempDir, src)
	if !ok {
		return 0, nil
	}
	if _, err := os.Lstat(filepath.Join(ns, "restore-status.json")); err == nil {
		return 1, nil
	}
	return 0, nil
}

func backupNamespace(backupTempDir string, src *Source) (string, bool) {
	if backupTempDir == "" {
		return "", false
	}
	ns, err := BackupNamespace(backupTempDir, src.root.Name())
	return ns, err == nil
}
