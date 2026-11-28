package backup

import (
	"cmp"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/bifrost0x/webssh/internal/store"
)

// A Go archive's database is attacker-controlled input: anyone holding an
// archive can add objects to it and write the manifest again, and the
// ledger checksums are those of the published migrations. SQLite runs a
// trigger or view of that database inside the restore's own statements,
// so the database may hold exactly the schema this build creates and
// nothing else. The structural check runs before any statement touches
// the database; the comparison with a freshly built reference runs after
// the schemas were brought up to date and before the restore semantics.

// schemaEntry is one row of sqlite_schema.
type schemaEntry struct {
	kind, name, table, sql string
}

func (e schemaEntry) String() string { return e.kind + " " + e.name }

// readSchema lists sqlite_schema in a stable order.
func readSchema(ctx context.Context, db *store.DB) ([]schemaEntry, error) {
	var out []schemaEntry
	err := db.Read(ctx, func(tx *store.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT type, name, tbl_name, sql FROM sqlite_schema`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var e schemaEntry
			var def sql.NullString
			if err := rows.Scan(&e.kind, &e.name, &e.table, &def); err != nil {
				return err
			}
			e.sql = def.String
			out = append(out, e)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("backup: read the database schema: %w", err)
	}
	slices.SortFunc(out, func(a, b schemaEntry) int {
		return cmp.Or(cmp.Compare(a.kind, b.kind), cmp.Compare(a.name, b.name))
	})
	return out, nil
}

// ownedName reports whether name belongs to a schema owner of this build
// (store.Owners), the store's ledger or SQLite's sequence table.
func ownedName(name string) bool {
	if name == "store_migrations" || name == "sqlite_sequence" {
		return true
	}
	for _, owner := range store.Owners {
		if strings.HasPrefix(name, owner+"_") {
			return true
		}
	}
	return false
}

// checkObjects refuses every object this build never creates: triggers,
// views, virtual tables and anything outside the owners' prefixes.
func checkObjects(entries []schemaEntry) error {
	for _, e := range entries {
		name := e.name
		if e.kind == "index" && strings.HasPrefix(name, "sqlite_autoindex_"+e.table+"_") {
			name = e.table // the index SQLite creates for a constraint
		}
		ok := (e.kind == "table" || e.kind == "index") && ownedName(name) && ownedName(e.table) &&
			!strings.HasPrefix(strings.ToUpper(strings.TrimSpace(e.sql)), "CREATE VIRTUAL")
		if !ok {
			return fmt.Errorf("%w: database: unexpected schema object %s", ErrInvalid, e)
		}
	}
	return nil
}

// checkStructure is checkObjects on an open database.
func checkStructure(ctx context.Context, db *store.DB) error {
	entries, err := readSchema(ctx, db)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	return checkObjects(entries)
}

// matchReference compares the schema of db, already brought up to
// schemas, with a database built from schemas alone in a temporary
// directory below dir. Any extra, missing or changed object refuses the
// archive.
func matchReference(ctx context.Context, db *store.DB, schemas []store.Schema, dir string) error {
	got, err := readSchema(ctx, db)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	want, err := referenceSchema(ctx, schemas, dir)
	if err != nil {
		return err
	}
	for _, e := range got {
		if !slices.Contains(want, e) {
			return fmt.Errorf("%w: database: schema object %s differs from this release's schema", ErrInvalid, e)
		}
	}
	for _, e := range want {
		if !slices.Contains(got, e) {
			return fmt.Errorf("%w: database: schema object %s is missing", ErrInvalid, e)
		}
	}
	return nil
}

func referenceSchema(ctx context.Context, schemas []store.Schema, dir string) ([]schemaEntry, error) {
	tmp, err := os.MkdirTemp(dir, ".webssh-schema-")
	if err != nil {
		return nil, fmt.Errorf("backup: build the reference schema: %w", err)
	}
	defer os.RemoveAll(tmp)
	ref, err := store.Open(ctx, filepath.Join(tmp, "reference.db"), store.Options{})
	if err != nil {
		return nil, fmt.Errorf("backup: build the reference schema: %w", err)
	}
	entries, err := func() ([]schemaEntry, error) {
		if err := ref.ApplyAll(ctx, schemas...); err != nil {
			return nil, err
		}
		return readSchema(ctx, ref)
	}()
	if err := errors.Join(err, ref.Close()); err != nil {
		return nil, fmt.Errorf("backup: build the reference schema: %w", err)
	}
	return entries, nil
}
