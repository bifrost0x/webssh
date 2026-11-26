package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Migration is one versioned schema change of one owner. Versions start at
// 1 and have no gaps. An applied migration is never edited: Apply compares
// its checksum and refuses a changed one.
type Migration struct {
	Version int
	SQL     string
}

// Schema is what a capability registers: its owner name and its
// migrations, from Migrations() in the capability's schema.go.
type Schema struct {
	Owner      string
	Migrations []Migration
}

// Owners is the closed list of schema owners. Each owner's tables, indexes,
// views and triggers are named "<owner>_…"; Apply rejects a migration that
// creates, changes or drops any other object. No owner is a prefix of
// another, and none contains "_", so the prefixes cannot overlap. A new
// owner is a contract change (docs/architecture/m1-contracts.md).
var Owners = []string{
	"accounts", "audit", "auth", "authlocal", "hostkey", "hostops", "hosts",
	"migrate", "operations", "session", "settings", "stepup", "terminal",
	"totp", "vault", "webauthn",
	// M2 contracts: identity and operation.
	"authgithub", "authldap", "authoidc", "backup",
	// M2 runtime: the durable state of the background jobs.
	"jobs",
}

// ledgerTable records applied migrations. It belongs to the store itself.
const ledgerTable = "store_migrations"

const createLedger = `CREATE TABLE IF NOT EXISTS ` + ledgerTable + ` (
	owner TEXT NOT NULL,
	version INTEGER NOT NULL,
	checksum TEXT NOT NULL,
	PRIMARY KEY (owner, version)
) STRICT`

// ErrMigration marks a migration set that cannot be applied as given.
var ErrMigration = errors.New("store: invalid migration")

func checksum(m Migration) string {
	sum := sha256.Sum256([]byte(m.SQL))
	return hex.EncodeToString(sum[:])
}

func validate(owner string, ms []Migration) error {
	if !slices.Contains(Owners, owner) {
		return fmt.Errorf("%w: unknown owner %q", ErrMigration, owner)
	}
	for i, m := range ms {
		if m.Version != i+1 {
			return fmt.Errorf("%w: %s: migration %d has version %d", ErrMigration, owner, i+1, m.Version)
		}
		if strings.TrimSpace(m.SQL) == "" {
			return fmt.Errorf("%w: %s: migration %d is empty", ErrMigration, owner, m.Version)
		}
	}
	return nil
}

// Apply brings owner's schema up to date. Each pending migration runs in
// its own write transaction together with its ledger entry, so a failed
// migration leaves the schema at the previous version. Apply fails when an
// applied migration was changed or removed, or when a migration touches an
// object outside the owner's prefix.
func (db *DB) Apply(ctx context.Context, owner string, ms []Migration) error {
	if err := validate(owner, ms); err != nil {
		return err
	}
	applied, err := db.appliedChecksums(ctx, owner)
	if err != nil {
		return err
	}
	if len(applied) > len(ms) {
		return fmt.Errorf("%w: %s: database is at version %d, code knows %d", ErrMigration, owner, len(applied), len(ms))
	}
	for i, m := range ms {
		if i < len(applied) {
			if applied[i] != checksum(m) {
				return fmt.Errorf("%w: %s: applied migration %d was changed", ErrMigration, owner, m.Version)
			}
			continue
		}
		if err := db.Write(ctx, func(tx *Tx) error { return applyOne(ctx, tx, owner, m) }); err != nil {
			return err
		}
	}
	return nil
}

// ApplyAll applies every schema in order.
func (db *DB) ApplyAll(ctx context.Context, schemas ...Schema) error {
	for _, s := range schemas {
		if err := db.Apply(ctx, s.Owner, s.Migrations); err != nil {
			return err
		}
	}
	return nil
}

func (db *DB) appliedChecksums(ctx context.Context, owner string) ([]string, error) {
	var sums []string
	err := db.Write(ctx, func(tx *Tx) error {
		if _, err := tx.ExecContext(ctx, createLedger); err != nil {
			return fmt.Errorf("store: create ledger: %w", err)
		}
		rows, err := tx.QueryContext(ctx, `SELECT version, checksum FROM `+ledgerTable+` WHERE owner = ? ORDER BY version`, owner)
		if err != nil {
			return fmt.Errorf("store: read ledger: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var v int
			var sum string
			if err := rows.Scan(&v, &sum); err != nil {
				return fmt.Errorf("store: read ledger: %w", err)
			}
			if v != len(sums)+1 {
				return fmt.Errorf("%w: %s: ledger has a gap at version %d", ErrMigration, owner, len(sums)+1)
			}
			sums = append(sums, sum)
		}
		return rows.Err()
	})
	return sums, err
}

func applyOne(ctx context.Context, tx *Tx, owner string, m Migration) error {
	before, err := schemaObjects(ctx, tx)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, m.SQL); err != nil {
		return fmt.Errorf("store: %s migration %d: %w", owner, m.Version, err)
	}
	after, err := schemaObjects(ctx, tx)
	if err != nil {
		return err
	}
	for name, obj := range after {
		if before[name] != obj && !obj.ownedBy(owner) {
			return fmt.Errorf("%w: %s migration %d changes %q outside its prefix", ErrMigration, owner, m.Version, name)
		}
	}
	for name, obj := range before {
		if _, kept := after[name]; !kept && !obj.ownedBy(owner) {
			return fmt.Errorf("%w: %s migration %d drops %q outside its prefix", ErrMigration, owner, m.Version, name)
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO `+ledgerTable+` (owner, version, checksum) VALUES (?, ?, ?)`, owner, m.Version, checksum(m)); err != nil {
		return fmt.Errorf("store: record %s migration %d: %w", owner, m.Version, err)
	}
	return nil
}

// object is one entry of sqlite_schema.
type object struct {
	name, table, sql string
}

// ownedBy reports whether a schema object belongs to owner: its name and
// the table it belongs to (indexes, triggers) carry the owner's prefix.
// Indexes that SQLite creates for constraints are named after their table.
func (o object) ownedBy(owner string) bool {
	prefix := owner + "_"
	name := strings.TrimPrefix(o.name, "sqlite_autoindex_")
	return strings.HasPrefix(name, prefix) && strings.HasPrefix(o.table, prefix)
}

// schemaObjects maps every schema object name to its entry.
func schemaObjects(ctx context.Context, tx *Tx) (map[string]object, error) {
	rows, err := tx.QueryContext(ctx, `SELECT name, tbl_name, sql FROM sqlite_schema`)
	if err != nil {
		return nil, fmt.Errorf("store: read schema: %w", err)
	}
	defer rows.Close()
	objects := map[string]object{}
	for rows.Next() {
		var o object
		var def sql.NullString
		if err := rows.Scan(&o.name, &o.table, &def); err != nil {
			return nil, fmt.Errorf("store: read schema: %w", err)
		}
		o.sql = def.String
		objects[o.name] = o
	}
	return objects, rows.Err()
}
