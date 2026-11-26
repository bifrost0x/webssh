package accounts

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"time"

	"github.com/bifrost0x/webssh/internal/store"
)

// Retained copies of deleted accounts. Like the Python release, which
// moved a deleted account's files to DATA_DIR/deleted_users/, the Go
// release keeps a copy of every row it deletes: before the rows are
// removed, they are written to DATA_DIR/go/deleted_users/<id>-<UTC time>/
// (directory 0700, files 0600), one JSON-lines file per table and a
// manifest with the row count and SHA-256 of each file. Values are copied
// as stored: sealed secrets stay sealed with the installation's keyring,
// password hashes stay hashes; nothing is decrypted. The copy is read back
// and checked before the deletion, and the deletion must remove exactly
// the rows the copy holds. There is no automatic cleanup; an operator
// removes a copy, as with the Python quarantine.

// RetainFormat names the manifest format.
const RetainFormat = "webssh-go-deleted-account"

const (
	retainVersion  = 1
	manifestName   = "manifest.json"
	maxRetainedRow = 16 << 20
)

// Retainer copies the rows of an account before they are deleted, inside
// the deletion's transaction.
type Retainer interface {
	RetainTx(ctx context.Context, tx *store.Tx, acc Account, tables []string) (Retained, error)
}

// Retained is a written and verified copy.
type Retained struct {
	// Name is the directory name below the retain root.
	Name string
	// Rows are the copied rows per table.
	Rows map[string]int64
	// Discard removes the copy again when the deletion does not commit.
	Discard func() error
}

// Manifest describes a retained copy.
type Manifest struct {
	Format      string                   `json:"format"`
	Version     int                      `json:"version"`
	UserID      int64                    `json:"user_id"`
	Username    string                   `json:"username"`
	Incarnation string                   `json:"incarnation"`
	DeletedAt   string                   `json:"deleted_at"`
	Tables      map[string]ManifestTable `json:"tables"`
}

// ManifestTable is one table of a retained copy.
type ManifestTable struct {
	File   string `json:"file"`
	Rows   int64  `json:"rows"`
	SHA256 string `json:"sha256"`
}

// RetainDir writes retained copies below Root (DATA_DIR/go/deleted_users).
type RetainDir struct {
	Root string
	Now  func() time.Time
}

func (d RetainDir) now() time.Time {
	if d.Now != nil {
		return d.Now().UTC()
	}
	return time.Now().UTC()
}

// RetainTx implements Retainer: it copies the account row and the
// account's rows of every listed table. Every file operation goes through
// an os.Root at the retain directory, so no name can leave it.
func (d RetainDir) RetainTx(ctx context.Context, tx *store.Tx, acc Account, tables []string) (Retained, error) {
	if d.Root == "" {
		return Retained{}, errors.New("accounts: retain: no directory for deleted accounts")
	}
	if err := os.MkdirAll(d.Root, 0o700); err != nil {
		return Retained{}, fmt.Errorf("accounts: retain: %w", err)
	}
	root, err := os.OpenRoot(d.Root)
	if err != nil {
		return Retained{}, fmt.Errorf("accounts: retain: %w", err)
	}
	defer root.Close()
	if err := root.Chmod(".", 0o700); err != nil { // #nosec G302 -- a directory needs the search bit
		return Retained{}, fmt.Errorf("accounts: retain: %w", err)
	}
	at := d.now()
	name := strconv.FormatInt(acc.ID, 10) + "-" + at.Format("20060102T150405Z")
	if _, err := root.Lstat(name); !errors.Is(err, os.ErrNotExist) {
		return Retained{}, fmt.Errorf("accounts: retain: %s exists", name)
	}
	partial := "." + name + ".partial"
	if err := root.Mkdir(partial, 0o700); err != nil {
		return Retained{}, fmt.Errorf("accounts: retain: %w", err)
	}
	ok := false
	defer func() {
		if !ok {
			_ = root.RemoveAll(partial)
		}
	}()
	dir, err := root.OpenRoot(partial)
	if err != nil {
		return Retained{}, fmt.Errorf("accounts: retain: %w", err)
	}
	defer dir.Close()
	m := Manifest{Format: RetainFormat, Version: retainVersion, UserID: acc.ID, Username: acc.Username,
		Incarnation: acc.Incarnation, DeletedAt: at.Format(time.RFC3339Nano), Tables: map[string]ManifestTable{}}
	all := append([]string{"accounts_users"}, tables...)
	for _, table := range all {
		if !tableName.MatchString(table) {
			return Retained{}, fmt.Errorf("accounts: retain: unexpected table name %q", table)
		}
		column := OwnerColumn
		if table == "accounts_users" {
			column = "id"
		}
		mt, err := writeTable(ctx, tx, dir, table, column, acc.ID)
		if err != nil {
			return Retained{}, err
		}
		m.Tables[table] = mt
	}
	raw, err := json.Marshal(m, json.Deterministic(true))
	if err != nil {
		return Retained{}, fmt.Errorf("accounts: retain manifest: %w", err)
	}
	if err := writeFile(dir, manifestName, raw); err != nil {
		return Retained{}, err
	}
	if err := verifyRetained(dir, acc.ID); err != nil {
		return Retained{}, err
	}
	if err := syncDir(dir); err != nil {
		return Retained{}, err
	}
	if err := root.Rename(partial, name); err != nil {
		return Retained{}, fmt.Errorf("accounts: retain: %w", err)
	}
	if err := syncDir(root); err != nil {
		_ = root.RemoveAll(name)
		return Retained{}, err
	}
	ok = true
	rows := map[string]int64{}
	for t, mt := range m.Tables {
		rows[t] = mt.Rows
	}
	rootPath := d.Root
	discard := func() error {
		r, err := os.OpenRoot(rootPath)
		if err != nil {
			return err
		}
		defer r.Close()
		return r.RemoveAll(name)
	}
	return Retained{Name: name, Rows: rows, Discard: discard}, nil
}

// writeTable writes the rows of one table as JSON lines and returns its
// manifest entry. BLOB values are written as {"base64": "..."}.
func writeTable(ctx context.Context, tx *store.Tx, dir *os.Root, table, column string, id int64) (ManifestTable, error) {
	// #nosec G202 -- table and column are checked identifiers (tableName, OwnerColumn, "id").
	rows, err := tx.QueryContext(ctx, `SELECT * FROM "`+table+`" WHERE `+column+` = ?`, id)
	if err != nil {
		return ManifestTable{}, fmt.Errorf("accounts: retain %s: %w", table, err)
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return ManifestTable{}, fmt.Errorf("accounts: retain %s: %w", table, err)
	}
	var buf bytes.Buffer
	var n int64
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return ManifestTable{}, fmt.Errorf("accounts: retain %s: %w", table, err)
		}
		row := make(map[string]any, len(cols))
		for i, c := range cols {
			if b, ok := vals[i].([]byte); ok {
				row[c] = map[string]string{"base64": base64.StdEncoding.EncodeToString(b)}
				continue
			}
			row[c] = vals[i]
		}
		line, err := json.Marshal(row, json.Deterministic(true))
		if err != nil {
			return ManifestTable{}, fmt.Errorf("accounts: retain %s: %w", table, err)
		}
		buf.Write(line)
		buf.WriteByte('\n')
		n++
	}
	if err := rows.Err(); err != nil {
		return ManifestTable{}, fmt.Errorf("accounts: retain %s: %w", table, err)
	}
	file := table + ".jsonl"
	if err := writeFile(dir, file, buf.Bytes()); err != nil {
		return ManifestTable{}, err
	}
	sum := sha256.Sum256(buf.Bytes())
	return ManifestTable{File: file, Rows: n, SHA256: hex.EncodeToString(sum[:])}, nil
}

// writeFile creates name in dir with mode 0600 and syncs it.
func writeFile(dir *os.Root, name string, data []byte) error {
	f, err := dir.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("accounts: retain: %w", err)
	}
	_, werr := f.Write(data)
	serr := f.Sync()
	cerr := f.Close()
	if err := errors.Join(werr, serr, cerr); err != nil {
		return fmt.Errorf("accounts: retain %s: %w", name, err)
	}
	return nil
}

func syncDir(dir *os.Root) error {
	f, err := dir.Open(".")
	if err != nil {
		return fmt.Errorf("accounts: retain: %w", err)
	}
	defer f.Close()
	if err := f.Sync(); err != nil && !errors.Is(err, os.ErrInvalid) {
		return fmt.Errorf("accounts: retain: sync: %w", err)
	}
	return nil
}

// VerifyRetained reads the copy in dir back and checks the manifest:
// format, the account, and every file's row count and SHA-256; every line
// must be a JSON object.
func VerifyRetained(dir string, userID int64) error {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return fmt.Errorf("accounts: verify retained copy: %w", err)
	}
	defer root.Close()
	return verifyRetained(root, userID)
}

func verifyRetained(dir *os.Root, userID int64) error {
	raw, err := dir.ReadFile(manifestName)
	if err != nil {
		return fmt.Errorf("accounts: verify retained copy: %w", err)
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return fmt.Errorf("accounts: verify retained copy: %w", err)
	}
	if m.Format != RetainFormat || m.Version != retainVersion || m.UserID != userID || m.Tables["accounts_users"].Rows != 1 {
		return errors.New("accounts: verify retained copy: manifest does not describe the account")
	}
	for table, mt := range m.Tables {
		if !tableName.MatchString(table) || mt.File != table+".jsonl" {
			return fmt.Errorf("accounts: verify retained copy: %q: unexpected file %q", table, mt.File)
		}
		f, err := dir.Open(mt.File)
		if err != nil {
			return fmt.Errorf("accounts: verify retained copy: %w", err)
		}
		h := sha256.New()
		sc := bufio.NewScanner(io.TeeReader(f, h))
		sc.Buffer(make([]byte, 64<<10), maxRetainedRow)
		var n int64
		for sc.Scan() {
			var row map[string]any
			if err := json.Unmarshal(sc.Bytes(), &row); err != nil {
				_ = f.Close()
				return fmt.Errorf("accounts: verify retained copy: %s line %d: %w", table, n+1, err)
			}
			n++
		}
		err = errors.Join(sc.Err(), f.Close())
		if err != nil {
			return fmt.Errorf("accounts: verify retained copy: %s: %w", table, err)
		}
		if n != mt.Rows || hex.EncodeToString(h.Sum(nil)) != mt.SHA256 {
			return fmt.Errorf("accounts: verify retained copy: %s does not match the manifest", table)
		}
	}
	return nil
}
