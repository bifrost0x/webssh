package hostkey

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/store"
)

// Store is the trust store of host keys: the global file and one file per
// user, evaluated in layers (user first). It provides client.HostKeys to
// the dialer. It is safe for concurrent use; writes are serialized by the
// database.
type Store struct {
	db     *store.DB
	now    func() time.Time
	logger *slog.Logger
	// revisionKey makes deletion-impact revisions opaque and valid for
	// this process only, as in the Python release.
	revisionKey [32]byte
}

// New returns the store on db, which must have Schema applied.
func New(db *store.DB, logger *slog.Logger) *Store {
	if logger == nil {
		logger = slog.Default()
	}
	s := &Store{db: db, now: time.Now, logger: logger}
	_, _ = rand.Read(s.revisionKey[:]) // never fails (crypto/rand)
	return s
}

// rawFile is one stored known_hosts file.
type rawFile struct {
	raw      []byte
	modified time.Time
	present  bool
}

type querier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func readFile(ctx context.Context, q querier, scope Scope, owner int64) (rawFile, error) {
	var f rawFile
	var us int64
	err := q.QueryRowContext(ctx, `SELECT raw, modified_us FROM hostkey_files WHERE scope = ? AND user_id = ?`, string(scope), owner).Scan(&f.raw, &us)
	if errors.Is(err, sql.ErrNoRows) {
		return rawFile{}, nil
	}
	if err != nil {
		return rawFile{}, fault.Wrap(fault.StorageError, err, "")
	}
	f.present = true
	f.modified = time.UnixMicro(us).UTC()
	return f, nil
}

func writeFile(ctx context.Context, tx *store.Tx, scope Scope, owner int64, raw []byte, modified time.Time) error {
	if raw == nil {
		raw = []byte{}
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO hostkey_files (scope, user_id, raw, modified_us) VALUES (?, ?, ?, ?)
ON CONFLICT (scope, user_id) DO UPDATE SET raw = excluded.raw, modified_us = excluded.modified_us`,
		string(scope), owner, raw, modified.UnixMicro())
	if err != nil {
		return fault.Wrap(fault.StorageError, err, "")
	}
	return nil
}

// files are the two layers of one user, raw and parsed.
type files struct {
	global, user             rawFile
	globalParsed, userParsed *File
}

func (f files) trust() Trust { return Trust{User: f.userParsed, Global: f.globalParsed} }

func (s *Store) load(ctx context.Context, q querier, owner int64) (files, error) {
	if owner <= 0 {
		return files{}, fault.New(fault.InvalidRequest, "")
	}
	var f files
	var err error
	if f.global, err = readFile(ctx, q, ScopeGlobal, 0); err != nil {
		return files{}, err
	}
	if f.user, err = readFile(ctx, q, ScopeUser, owner); err != nil {
		return files{}, err
	}
	if f.globalParsed, err = Parse(f.global.raw); err != nil {
		return files{}, s.unusable(ctx, ScopeGlobal, owner, err)
	}
	if f.userParsed, err = Parse(f.user.raw); err != nil {
		return files{}, s.unusable(ctx, ScopeUser, owner, err)
	}
	return f, nil
}

// unusable reports a file that does not parse. Trust is never evaluated
// on part of a file: every connection of the user fails until the file is
// repaired, and the message names the line.
func (s *Store) unusable(ctx context.Context, scope Scope, owner int64, err error) error {
	s.logger.WarnContext(ctx, "known hosts file is invalid", "scope", string(scope), "user_id", owner, "error", err)
	which := "your known hosts"
	if scope == ScopeGlobal {
		which = "the global known hosts"
	}
	if fe, ok := errors.AsType[*InvalidFileError](err); ok && fe.Line > 0 {
		return fault.Wrap(fault.StorageError, err, fmt.Sprintf("The saved host keys cannot be used: line %d of %s is invalid.", fe.Line, which))
	}
	return fault.Wrap(fault.StorageError, err, fmt.Sprintf("The saved host keys cannot be used: %s are not valid UTF-8.", which))
}

func (s *Store) read(ctx context.Context, owner int64) (files, error) {
	var f files
	err := s.db.Read(ctx, func(tx *store.Tx) error {
		var err error
		f, err = s.load(ctx, tx, owner)
		return err
	})
	return f, err
}

func verdictError(v Verdict) error {
	switch v {
	case Changed:
		return fault.New(fault.HostKeyChanged, "")
	case Revoked:
		return fault.New(fault.HostKeyRevoked, "")
	}
	return nil
}

// Known reports whether key is trusted for host:port and owner. host is
// the canonical host name. It returns false and nil when no trust exists
// for the host, and host_key_changed or host_key_revoked when trust exists
// but not for this key.
func (s *Store) Known(ctx context.Context, owner int64, host string, port int, key ssh.PublicKey) (bool, error) {
	f, err := s.read(ctx, owner)
	if err != nil {
		return false, err
	}
	v := f.trust().Verify(LookupName(host, port), key)
	if v == Trusted {
		return true, nil
	}
	return false, verdictError(v)
}

// Record trusts key for host:port after the user accepted it. It re-checks
// inside the write transaction, so a key another session recorded
// meanwhile wins and this one fails with host_key_changed. The line is
// appended without rewriting the rest of the file.
func (s *Store) Record(ctx context.Context, owner int64, host string, port int, key ssh.PublicKey) error {
	name := LookupName(host, port)
	return s.db.Write(ctx, func(tx *store.Tx) error {
		f, err := s.load(ctx, tx, owner)
		if err != nil {
			return err
		}
		switch v := f.trust().Verify(name, key); v {
		case Trusted:
			return nil
		case Changed, Revoked:
			return verdictError(v)
		}
		raw := append([]byte(nil), f.user.raw...)
		if len(raw) > 0 && raw[len(raw)-1] != '\n' {
			raw = append(raw, '\n')
		}
		raw = append(raw, FormatLine(name, key)...)
		return writeFile(ctx, tx, ScopeUser, owner, raw, s.now())
	})
}

// Preferred orders the allowed host-key algorithms with the types trusted
// for host:port first, so the server presents a key that can be verified.
func (s *Store) Preferred(ctx context.Context, owner int64, host string, port int, allowed []string) ([]string, error) {
	f, err := s.read(ctx, owner)
	if err != nil {
		return nil, err
	}
	return f.trust().PreferredAlgorithms(LookupName(host, port), allowed), nil
}

// ImportFile stores a known_hosts file taken over from the Python release,
// inside the migration's transaction. The file must parse completely; an
// invalid line fails with an *InvalidFileError that names it, and nothing
// is stored. owner is 0 for the global file.
func ImportFile(ctx context.Context, tx *store.Tx, scope Scope, owner int64, raw []byte, modified time.Time) error {
	if (scope == ScopeGlobal) != (owner == 0) || (scope != ScopeGlobal && scope != ScopeUser) || owner < 0 {
		return fmt.Errorf("hostkey: import: invalid scope %q for owner %d", scope, owner)
	}
	if _, err := Parse(raw); err != nil {
		return err
	}
	current, err := readFile(ctx, tx, scope, owner)
	if err != nil {
		return err
	}
	if current.present {
		return fmt.Errorf("hostkey: import: %s file of user %d already exists", scope, owner)
	}
	return writeFile(ctx, tx, scope, owner, raw, modified)
}
