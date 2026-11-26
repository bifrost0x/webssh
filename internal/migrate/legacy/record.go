package legacy

import (
	"context"
	"database/sql"
	json "encoding/json/v2"
	"errors"
	"fmt"

	"github.com/bifrost0x/webssh/internal/store"
)

// RecordSchema is the schema of the migration's own tables in the Go
// database (owner "migrate"):
//
//   - migrate_record, the record of the completed migration, written in
//     the same transaction as the last migration step, so that the Go
//     database and its record appear together (section 5.2 step 10.1);
//   - migrate_keyring, the key identifier of the keyring the database's
//     sealed records belong to (state S9), and whether the material lives
//     in go/; an installation that never had legacy data gets its row
//     from the composition root;
//   - migrate_settings, settings the migration derived from the previous
//     behaviour (D-01) that no other capability owns.
func RecordSchema() store.Schema {
	return store.Schema{Owner: "migrate", Migrations: []store.Migration{{
		Version: 1,
		SQL: `CREATE TABLE migrate_record (
	id INTEGER PRIMARY KEY CHECK (id = 1),
	format INTEGER NOT NULL,
	database_id TEXT NOT NULL,
	go_release TEXT NOT NULL,
	started_at TEXT NOT NULL,
	completed_at TEXT NOT NULL,
	source_digest TEXT NOT NULL,
	listing TEXT NOT NULL,
	schema_shape TEXT NOT NULL,
	coverage TEXT NOT NULL,
	pending TEXT NOT NULL,
	report TEXT NOT NULL,
	replaced_database TEXT NOT NULL
) STRICT;
CREATE TABLE migrate_keyring (
	id INTEGER PRIMARY KEY CHECK (id = 1),
	key_id TEXT NOT NULL CHECK (key_id <> ''),
	material_in_go INTEGER NOT NULL CHECK (material_in_go IN (0, 1))
) STRICT;
CREATE TABLE migrate_settings (
	key TEXT PRIMARY KEY,
	value TEXT NOT NULL,
	rule TEXT NOT NULL,
	evidence TEXT NOT NULL
) STRICT`,
	}}}
}

// recordFormat is the format version of migrate_record.
const recordFormat = 1

// Record is the record of a completed migration.
type Record struct {
	Format           int
	DatabaseID       string
	GoRelease        string
	StartedAt        string
	CompletedAt      string
	SourceDigest     string
	Listing          []FileStat
	SchemaShape      SchemaShape
	Coverage         []Coverage
	Pending          []Pending
	Report           Report
	ReplacedDatabase string
}

func writeRecord(ctx context.Context, tx *store.Tx, r Record) error {
	listing, err1 := json.Marshal(r.Listing)
	shape, err2 := json.Marshal(r.SchemaShape)
	coverage, err3 := json.Marshal(r.Coverage)
	pending, err4 := json.Marshal(r.Pending)
	report, err5 := json.Marshal(r.Report)
	if err := errors.Join(err1, err2, err3, err4, err5); err != nil {
		return fmt.Errorf("legacy: encode the migration record: %w", err)
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO migrate_record (id, format, database_id, go_release, started_at,
completed_at, source_digest, listing, schema_shape, coverage, pending, report, replaced_database)
VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, recordFormat, r.DatabaseID, r.GoRelease, r.StartedAt,
		r.CompletedAt, r.SourceDigest, string(listing), string(shape), string(coverage), string(pending),
		string(report), r.ReplacedDatabase)
	if err != nil {
		return fmt.Errorf("legacy: write the migration record: %w", err)
	}
	return nil
}

// queryer is satisfied by *store.Tx and *sql.DB, so that the state
// evaluation can read a database it opened read-only.
type queryer interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// readRecord returns the migration record, or nil when the database has
// none (a Go-native installation, or a database without the migrate
// tables).
func readRecord(ctx context.Context, q queryer) (*Record, error) {
	var has int
	if err := q.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_schema WHERE type = 'table' AND name = 'migrate_record'`).Scan(&has); err != nil {
		return nil, fmt.Errorf("legacy: read the migration record: %w", err)
	}
	if has == 0 {
		return nil, nil
	}
	var r Record
	var listing, shape, coverage, pending, report string
	err := q.QueryRowContext(ctx, `SELECT format, database_id, go_release, started_at, completed_at, source_digest,
listing, schema_shape, coverage, pending, report, replaced_database FROM migrate_record WHERE id = 1`).Scan(
		&r.Format, &r.DatabaseID, &r.GoRelease, &r.StartedAt, &r.CompletedAt, &r.SourceDigest,
		&listing, &shape, &coverage, &pending, &report, &r.ReplacedDatabase)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("legacy: read the migration record: %w", err)
	}
	if r.Format != recordFormat {
		return nil, fmt.Errorf("legacy: migration record format %d is not supported", r.Format)
	}
	if err := errors.Join(json.Unmarshal([]byte(listing), &r.Listing), json.Unmarshal([]byte(shape), &r.SchemaShape),
		json.Unmarshal([]byte(coverage), &r.Coverage), json.Unmarshal([]byte(pending), &r.Pending),
		json.Unmarshal([]byte(report), &r.Report)); err != nil {
		return nil, fmt.Errorf("legacy: decode the migration record: %w", err)
	}
	return &r, nil
}

// writeKeyID stores the key identifier of the ring that sealed the
// database's records.
func writeKeyID(ctx context.Context, tx *store.Tx, keyID string) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO migrate_keyring (id, key_id, material_in_go) VALUES (1, ?, 0)
ON CONFLICT (id) DO UPDATE SET key_id = excluded.key_id`, keyID)
	if err != nil {
		return fmt.Errorf("legacy: store the key identifier: %w", err)
	}
	return nil
}

// readKeyID returns the stored key identifier, or "" when there is none.
func readKeyID(ctx context.Context, q queryer) (string, error) {
	var has int
	if err := q.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_schema WHERE type = 'table' AND name = 'migrate_keyring'`).Scan(&has); err != nil {
		return "", fmt.Errorf("legacy: read the key identifier: %w", err)
	}
	if has == 0 {
		return "", nil
	}
	var id string
	err := q.QueryRowContext(ctx, `SELECT key_id FROM migrate_keyring WHERE id = 1`).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("legacy: read the key identifier: %w", err)
	}
	return id, nil
}

// RecordKeyID stores the key identifier for a Go database that has no
// migration, at the first start of a new installation (composition root).
// The database must have RecordSchema applied.
func RecordKeyID(ctx context.Context, db *store.DB, keyID string) error {
	return db.Write(ctx, func(tx *store.Tx) error { return writeKeyID(ctx, tx, keyID) })
}

// StoredKeyID returns the key identifier of db, or "" when none is
// stored.
func StoredKeyID(ctx context.Context, db *store.DB) (string, error) {
	var id string
	err := db.Read(ctx, func(tx *store.Tx) error {
		var err error
		id, err = readKeyID(ctx, tx)
		return err
	})
	return id, err
}

// writeSetting stores one derived setting (section 6).
func writeSetting(ctx context.Context, tx *store.Tx, s MaterialisedSetting) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO migrate_settings (key, value, rule, evidence) VALUES (?, ?, ?, ?)`,
		s.Setting, s.Value, s.Rule, s.Evidence)
	if err != nil {
		return fmt.Errorf("legacy: store setting %s: %w", s.Setting, err)
	}
	return nil
}

// Setting returns a setting the migration derived (for example
// SettingIgnoreOriginScheme) and whether it is stored.
func Setting(ctx context.Context, db *store.DB, key string) (string, bool, error) {
	var value string
	found := false
	err := db.Read(ctx, func(tx *store.Tx) error {
		var has int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_schema WHERE type = 'table' AND name = 'migrate_settings'`).Scan(&has); err != nil || has == 0 {
			return err
		}
		err := tx.QueryRowContext(ctx, `SELECT value FROM migrate_settings WHERE key = ?`, key).Scan(&value)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		found = err == nil
		return err
	})
	if err != nil {
		return "", false, fmt.Errorf("legacy: read setting %s: %w", key, err)
	}
	return value, found, nil
}
