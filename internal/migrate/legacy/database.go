package legacy

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/bifrost0x/webssh/internal/store"
)

// ErrJournal reports a hot rollback journal or a non-empty WAL beside
// app.db: a Python transaction was interrupted. Go never recovers a
// legacy journal; the Python release must start and stop once
// (migration specification, section 5.2 step 4).
var ErrJournal = errors.New("legacy: app.db has an unfinished transaction journal")

// sqliteHeaderSize is the size of the SQLite database header.
const sqliteHeaderSize = 100

// openDatabase opens app.db read-only without writing anything into
// DATA_DIR. A rollback-journal database is opened with normal locking. A
// database in WAL mode would make SQLite create -wal and -shm files, so it
// is opened immutable once the WAL is known to be empty; nothing is lost,
// because an empty WAL holds no committed data.
func openDatabase(ctx context.Context, root *os.Root, private bool) (*sql.DB, error) {
	info, err := lstatChain(root, "app.db")
	if err != nil || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("legacy: data directory has no regular app.db: %w", errOr(err, ErrUnsafePath))
	}
	header, err := readHeader(root)
	if err != nil {
		return nil, err
	}
	wal := header[18] == 2 && header[19] == 2
	if !private {
		for _, side := range []string{"app.db-journal", "app.db-wal"} {
			si, err := lstatChain(root, side)
			switch {
			case errors.Is(err, ErrNotFound):
			case err != nil:
				return nil, err
			case !si.Mode().IsRegular():
				return nil, fmt.Errorf("%w: %q", ErrUnsafePath, side)
			case si.Size() > 0:
				return nil, fmt.Errorf("%w (%s)", ErrJournal, side)
			}
		}
	}
	mode := store.Shared
	if private || wal {
		mode = store.Immutable
	}
	return store.OpenReadOnly(ctx, root.Name()+string(os.PathSeparator)+"app.db", mode)
}

func readHeader(root *os.Root) ([]byte, error) {
	f, err := root.Open("app.db")
	if err != nil {
		return nil, fmt.Errorf("legacy: open app.db: %w", err)
	}
	defer f.Close()
	header := make([]byte, sqliteHeaderSize)
	if _, err := f.ReadAt(header, 0); err != nil || string(header[:16]) != "SQLite format 3\x00" {
		return nil, errors.New("legacy: app.db is not an SQLite 3 database")
	}
	return header, nil
}

func errOr(err, fallback error) error {
	if err != nil {
		return err
	}
	return fallback
}

// Schema is the shape of app.db as found, recorded in the migration report.
type Schema struct {
	Tables   map[string][]string // table name to its columns, in order
	Indexes  []string
	Triggers []string
	Views    []string
	// Other lists schema objects that are neither ordinary tables nor
	// the above, such as virtual and shadow tables ("type name").
	Other []string
}

// HasTable reports whether app.db has the table.
func (sc Schema) HasTable(name string) bool { _, ok := sc.Tables[name]; return ok }

// HasColumn reports whether a table has a column.
func (sc Schema) HasColumn(table, column string) bool {
	return slices.Contains(sc.Tables[table], column)
}

func inspectSchema(ctx context.Context, db *sql.DB) (Schema, error) {
	sc := Schema{Tables: map[string][]string{}}
	rows, err := db.QueryContext(ctx, `SELECT type, name FROM sqlite_schema ORDER BY type, name`)
	if err != nil {
		return sc, fmt.Errorf("legacy: inspect schema: %w", err)
	}
	var tables []string
	for rows.Next() {
		var typ, name string
		if err := rows.Scan(&typ, &name); err != nil {
			return sc, fmt.Errorf("legacy: inspect schema: %w", errors.Join(err, rows.Close()))
		}
		switch typ {
		case "table":
			tables = append(tables, name)
		case "index":
			sc.Indexes = append(sc.Indexes, name)
		case "trigger":
			sc.Triggers = append(sc.Triggers, name)
		case "view":
			sc.Views = append(sc.Views, name)
		}
	}
	err = errors.Join(rows.Err(), rows.Close())
	if err != nil {
		return sc, fmt.Errorf("legacy: inspect schema: %w", err)
	}
	if sc.Other, err = otherObjects(ctx, db); err != nil {
		return sc, err
	}
	for _, t := range tables {
		cols, err := tableColumns(ctx, db, t)
		if err != nil {
			return sc, err
		}
		sc.Tables[t] = cols
	}
	return sc, nil
}

func otherObjects(ctx context.Context, db *sql.DB) ([]string, error) {
	rows, err := db.QueryContext(ctx, `SELECT type, name FROM pragma_table_list WHERE schema = 'main' AND type NOT IN ('table', 'view') ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("legacy: inspect schema: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var typ, name string
		if err := rows.Scan(&typ, &name); err != nil {
			return nil, fmt.Errorf("legacy: inspect schema: %w", err)
		}
		out = append(out, typ+" "+name)
	}
	return out, rows.Err()
}

func tableColumns(ctx context.Context, db *sql.DB, table string) ([]string, error) {
	rows, err := db.QueryContext(ctx, `SELECT name FROM pragma_table_info(?)`, table)
	if err != nil {
		return nil, fmt.Errorf("legacy: inspect table %q: %w", table, err)
	}
	defer rows.Close()
	var cols []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return nil, fmt.Errorf("legacy: inspect table %q: %w", table, err)
		}
		cols = append(cols, c)
	}
	return cols, rows.Err()
}

// Tables returns the row count of every table in app.db, so the migration
// can account for each row it migrates, skips or discards.
func (s *Source) Tables(ctx context.Context) (map[string]int64, error) {
	counts := make(map[string]int64, len(s.schema.Tables))
	for name := range s.schema.Tables {
		if strings.HasPrefix(name, "sqlite_") {
			continue
		}
		var n int64
		// The name comes from sqlite_schema, which a restored archive
		// controls; it is quoted as an identifier, so it cannot change the
		// statement.
		quoted := `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
		if err := s.db.QueryRowContext(ctx, "SELECT count(*) FROM "+quoted).Scan(&n); err != nil { // #nosec G202 -- identifier quoted with "" escaping
			return nil, fmt.Errorf("legacy: count %q: %w", name, err)
		}
		counts[name] = n
	}
	return counts, nil
}

// CheckIntegrity runs SQLite's quick_check and requires the users table
// with the columns every Python release has. Triggers, views and other
// objects are tolerated in the live source and reported through Schema
// (migration specification, section 5.2 step 3); they never run, because
// the database is read with trusted_schema = OFF.
func (s *Source) CheckIntegrity(ctx context.Context) error {
	var result string
	if err := s.db.QueryRowContext(ctx, "PRAGMA quick_check").Scan(&result); err != nil {
		return fmt.Errorf("legacy: quick_check: %w", err)
	}
	if result != "ok" {
		return errors.New("legacy: database failed quick_check")
	}
	for _, column := range []string{"id", "username", "password_hash"} {
		if !s.schema.HasColumn("users", column) {
			return errors.New("legacy: app.db is not a WebSSH database")
		}
	}
	return nil
}

// CheckBackupDatabase is CheckIntegrity plus the strict rules of a Python
// restore (app/restore_database.py harden_imported_database): no
// triggers, no views, no virtual or shadow tables.
func (s *Source) CheckBackupDatabase(ctx context.Context) error {
	if len(s.schema.Triggers)+len(s.schema.Views)+len(s.schema.Other) > 0 {
		return fmt.Errorf("%w: database contains unsupported schema", ErrBackup)
	}
	return s.CheckIntegrity(ctx)
}
