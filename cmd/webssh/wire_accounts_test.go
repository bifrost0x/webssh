package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/bifrost0x/webssh/internal/accounts"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/store"
	"github.com/bifrost0x/webssh/internal/store/storetest"
)

// accountColumns are columns that name an account in some other way than
// accounts.OwnerColumn, with the reason they are not swept. A new column
// that names an account must be added here or renamed, so an account's
// rows cannot survive its deletion unnoticed.
var accountColumns = map[string]string{
	"accounts_quarantine.former_user_id": "index of a deleted account's legacy directory",
}

// Every store of the build is covered by the account deletion: per-account
// rows are keyed by user_id, the kept tables exist, and the factor tables
// of the MFA reset exist and are keyed by user_id.
func TestAccountDeletionCoversEveryStore(t *testing.T) {
	t.Parallel()
	db := storetest.Open(t, schemas()...)
	err := db.Read(t.Context(), func(tx *store.Tx) error {
		owned, err := accounts.OwnedTablesTx(t.Context(), tx)
		if err != nil {
			return err
		}
		for table := range accounts.DefaultKeep {
			if table != "accounts_users" && !slices.Contains(owned, table) {
				t.Errorf("kept table %s has no user_id column or does not exist", table)
			}
		}
		for _, table := range accounts.FactorTables {
			if !slices.Contains(owned, table) {
				t.Errorf("factor table %s has no user_id column or does not exist", table)
			}
		}
		rows, err := tx.QueryContext(t.Context(), `SELECT m.name, c.name FROM sqlite_schema AS m, pragma_table_info(m.name) AS c
			WHERE m.type = 'table' AND c.name <> 'user_id' AND (c.name LIKE '%user%' OR c.name LIKE '%owner%' OR c.name LIKE '%account%')`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var table, column string
			if err := rows.Scan(&table, &column); err != nil {
				return err
			}
			key := table + "." + column
			if _, ok := accountColumns[key]; ok || strings.HasSuffix(column, "username") || table == "store_migrations" {
				continue
			}
			t.Errorf("%s may name an account but is not swept by the account deletion", key)
		}
		return rows.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestLegacyUserDir(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "users", "user_4"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "users", "user_5"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	look := legacyUserDir(dir)
	if rel, ok := look(4); !ok || rel != "users/user_4" {
		t.Fatalf("%q %v", rel, ok)
	}
	for _, id := range []int64{5, 6} {
		if _, ok := look(id); ok {
			t.Errorf("user %d reported", id)
		}
	}
}

func TestTerminalAccessWithoutTerminal(t *testing.T) {
	t.Parallel()
	terminalAccess{}.EndAccount(3, principal.ReasonAccountLocked) // must not panic
}
