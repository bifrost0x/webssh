// Package legacy reads the data directory of the Python release of WebSSH
// for the one-time migration (ADR 0007, docs/architecture/migration-spec.md).
// It is the only package that knows the Python schema and file layout.
//
// Everything here reads; nothing writes to the legacy data. Files are opened
// through an os.Root and every path component is checked for symbolic
// links first (paths.go), and the database is opened read-only through
// internal/store without creating journal side files (database.go).
//
// Secret values are returned to the caller for re-encryption and
// verification. They are never logged, and errors never contain them.
//
// A Source is safe for concurrent use. Derivations that are expensive by
// design (PBKDF2, scrypt) run once per call; callers serialise vault
// imports, which use 128 MiB each.
package legacy

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
)

// ErrNotFound reports a legacy file that does not exist.
var ErrNotFound = errors.New("legacy: not found")

// Source is an opened legacy DATA_DIR.
type Source struct {
	root   *os.Root
	secret string
	db     *sql.DB
	schema Schema

	mu   sync.Mutex
	keys map[string][]byte // derived key material by purpose; see kdf.go
}

// Option configures Open.
type Option func(*options)

type options struct{ private bool }

// PrivateCopy marks dir as a private copy owned by the caller, such as a
// directory extracted from a backup: app.db is then opened as immutable
// without locking, whatever its journal mode.
func PrivateCopy() Option { return func(o *options) { o.private = true } }

// Open opens the legacy data directory dir. secret is the SECRET_KEY the
// Python release ran with, resolved as entrypoint.sh does (see
// SecretFromFile).
//
// Open fails (STOP in the migration specification) when the legacy source
// contains a symbolic link or a special file (section 5.3), when app.db
// has a hot journal or a non-empty WAL (section 5.2 step 4), or when a
// table the migration reads has a column the Python release does not know.
func Open(ctx context.Context, dir, secret string, opts ...Option) (*Source, error) {
	if secret == "" {
		return nil, errors.New("legacy: SECRET_KEY is empty")
	}
	var o options
	for _, opt := range opts {
		opt(&o)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("legacy: open data directory: %w", err)
	}
	s := &Source{root: root, secret: secret, keys: map[string][]byte{}}
	if err := s.open(ctx, o); err != nil {
		return nil, errors.Join(err, root.Close())
	}
	return s, nil
}

func (s *Source) open(ctx context.Context, o options) error {
	if err := s.CheckTree(); err != nil {
		return err
	}
	db, err := openDatabase(ctx, s.root, o.private)
	if err != nil {
		return err
	}
	s.db = db
	if s.schema, err = inspectSchema(ctx, db); err != nil {
		return errors.Join(err, db.Close())
	}
	if err := s.schema.checkKnownColumns(); err != nil {
		return errors.Join(err, db.Close())
	}
	return nil
}

// SecretFromFile reads DATA_DIR/secret_key the way entrypoint.sh does with
// "$(cat file)": the content without trailing newlines.
func SecretFromFile(dir string) (string, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return "", fmt.Errorf("legacy: open data directory: %w", err)
	}
	defer root.Close()
	data, err := readLimited(root, "secret_key", maxFileBytes)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(data), "\n"), nil
}

// Close releases the database and the directory handle.
func (s *Source) Close() error {
	return errors.Join(s.db.Close(), s.root.Close())
}

// Schema returns the shape of app.db detected at Open, for the migration
// report.
func (s *Source) Schema() Schema { return s.schema }

// readFile returns a legacy file below DATA_DIR. name uses forward slashes.
func (s *Source) readFile(name string) ([]byte, error) {
	return readLimited(s.root, name, maxFileBytes)
}

// userDir is the per-user directory of the Python release.
func userDir(userID int64) string { return fmt.Sprintf("users/user_%d", userID) }
