package backup

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/store"
)

// Secret rotation (C-BAK-08, ADR 0008, migration specification 4.9).
//
// rotate-secret-key replaces SECRET_KEY in DATA_DIR/secret_key and
// reseals every keyring record under the new key, keeping the keyring
// material. The database and the file cannot change in one step, so the
// new secret is first written to PendingSecretName in the Go directory.
// The commit point is the database transaction, which reseals every
// record and stores the new key identifier together:
//
//  1. write the pending secret (fsynced);
//  2. one transaction: reseal or remove every keyring record, check that
//     no value sealed under the old key remains, store the new key
//     identifier;
//  3. install the pending secret as DATA_DIR/secret_key (temporary file,
//     fsync, rename, fsync of the directory);
//  4. remove the pending secret.
//
// A crash before 2 leaves the old key everywhere and a stale pending
// file, which DiscardStaleRotation removes under the Go lock. A crash
// after 2 leaves a database under the new key and the old file;
// CompleteRotation, which every start runs before the key check, then
// installs the pending secret. No step loses a secret.

// PendingSecretName is the new SECRET_KEY of a rotation in progress,
// below the Go directory.
const PendingSecretName = "rotation-secret"

// Checkpoints of RotateSecret, for the crash tests.
const (
	PointPrepared  = "prepared"
	PointPending   = "pending_written"
	PointResealed  = "resealed" // inside the transaction, before the key identifier
	PointCommitted = "committed"
	PointInstalled = "installed"
	PointDone      = "done"
)

// RotationStep reseals or removes the keyring records of one capability
// inside the rotation transaction and returns how many it handled.
type RotationStep struct {
	Name string
	Run  func(ctx context.Context, tx *store.Tx, rt *keyring.Rotation) (int, error)
}

// RotateRequest is one rotation. The caller holds the Go lock, has
// checked that no legacy data exists (LegacyPurged), has written and
// verified the pre-rotation backup and has opened DB under Ring.
type RotateRequest struct {
	DataDir string
	DB      *store.DB
	// Ring is the current ring, verified against the database.
	Ring     *keyring.Ring
	Material []byte
	// LegacyPurged is true only when no legacy source exists: after
	// `webssh legacy purge`, or for an installation that never had one.
	LegacyPurged bool
	// NewSecret is the new SECRET_KEY; empty generates 32 random bytes as
	// 64 hex digits, as the Python release did.
	NewSecret []byte
	Steps     []RotationStep
	// WriteKeyID stores the key identifier in the rotation transaction.
	WriteKeyID func(ctx context.Context, tx *store.Tx, keyID string) error
	// Checkpoint is called at every Point*; only the crash tests set it.
	Checkpoint func(string)
}

// Rotated is the outcome of a rotation.
type Rotated struct {
	KeyID  string
	Counts map[string]int
}

// ErrRotationLeftover reports a value still sealed under the old key after
// every step ran: a capability that keeps keyring records is missing from
// the steps. Nothing was changed.
var ErrRotationLeftover = errors.New("backup: a stored value is still sealed under the old SECRET_KEY; nothing was changed")

func (r RotateRequest) point(p string) {
	if r.Checkpoint != nil {
		r.Checkpoint(p)
	}
}

// RotateSecret runs the rotation. On an error before the commit nothing
// but the pending file changed; after the commit the error says that the
// next start completes it.
func RotateSecret(ctx context.Context, r RotateRequest) (Rotated, error) {
	if r.DB == nil || r.Ring == nil || r.WriteKeyID == nil || len(r.Steps) == 0 {
		return Rotated{}, errors.New("backup: rotation needs the database, the ring, the steps and WriteKeyID")
	}
	secret := r.NewSecret
	if len(secret) == 0 {
		var b [32]byte
		_, _ = rand.Read(b[:]) // never fails (crypto/rand)
		secret = []byte(hex.EncodeToString(b[:]))
	}
	if err := checkSecret(secret); err != nil {
		return Rotated{}, err
	}
	to, err := keyring.Open(secret, r.Material)
	if err != nil {
		return Rotated{}, err
	}
	rt, err := keyring.NewRotation(r.Ring, to, r.LegacyPurged)
	if err != nil {
		return Rotated{}, err
	}
	goDir := filepath.Join(r.DataDir, keyring.GoDirName)
	pending := filepath.Join(goDir, PendingSecretName)
	if err := removeRegular(pending); err != nil {
		return Rotated{}, err
	}
	r.point(PointPrepared)
	if err := installSecretFile(pending, secret); err != nil {
		return Rotated{}, err
	}
	r.point(PointPending)
	var counts map[string]int
	err = r.DB.Write(ctx, func(tx *store.Tx) error {
		var err error
		if counts, err = resealTx(ctx, tx, rt, r.Steps); err != nil {
			return err
		}
		r.point(PointResealed)
		return r.WriteKeyID(ctx, tx, to.KeyID())
	})
	if err != nil {
		return Rotated{}, errors.Join(fmt.Errorf("backup: rotation not committed: %w", err), removeRegular(pending))
	}
	r.point(PointCommitted)
	if err := finishRotation(r.DataDir, secret, func() { r.point(PointInstalled) }); err != nil {
		return Rotated{}, fmt.Errorf("backup: the rotation is committed, but SECRET_KEY was not installed; "+
			"the next start of WebSSH installs it from %s: %w", pending, err)
	}
	r.point(PointDone)
	return Rotated{KeyID: to.KeyID(), Counts: counts}, nil
}

// resealTx runs every step in tx and checks that no value sealed under
// the old key remains. It returns how many records each step handled.
func resealTx(ctx context.Context, tx *store.Tx, rt *keyring.Rotation, steps []RotationStep) (map[string]int, error) {
	counts := map[string]int{}
	for _, s := range steps {
		n, err := s.Run(ctx, tx, rt)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", s.Name, err)
		}
		counts[s.Name] = n
	}
	left, err := sealedUnder(ctx, tx, rt.OldHeader())
	if err != nil {
		return nil, err
	}
	if left != "" {
		return nil, fmt.Errorf("%w (%s)", ErrRotationLeftover, left)
	}
	return counts, nil
}

// finishRotation installs the committed secret and removes the pending
// file.
func finishRotation(dataDir string, secret []byte, installed func()) error {
	if err := installSecretFile(filepath.Join(dataDir, secretFileName), secret); err != nil {
		return err
	}
	installed()
	return removeRegular(filepath.Join(dataDir, keyring.GoDirName, PendingSecretName))
}

// sealedUnder names the first table and column with a value that starts
// with header, or "" when there is none. It looks at every BLOB column of
// every table, so that a capability whose records the steps missed stops
// the rotation instead of losing its secrets.
func sealedUnder(ctx context.Context, tx *store.Tx, header []byte) (string, error) {
	type column struct{ table, name string }
	cols, err := func() ([]column, error) {
		rows, err := tx.QueryContext(ctx, `SELECT m.name, p.name FROM sqlite_schema m, pragma_table_info(m.name) p
WHERE m.type = 'table' AND upper(p.type) = 'BLOB' ORDER BY m.name, p.cid`)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var cols []column
		for rows.Next() {
			var c column
			if err := rows.Scan(&c.table, &c.name); err != nil {
				return nil, err
			}
			cols = append(cols, c)
		}
		return cols, rows.Err()
	}()
	if err != nil {
		return "", fmt.Errorf("backup: list sealed columns: %w", err)
	}
	for _, c := range cols {
		var n int
		q := `SELECT count(*) FROM "` + c.table + `" WHERE substr("` + c.name + `", 1, ?) = ?` // #nosec G202 -- names from sqlite_schema of Go's own tables
		if err := tx.QueryRowContext(ctx, q, len(header), header).Scan(&n); err != nil {
			return "", fmt.Errorf("backup: check %s.%s: %w", c.table, c.name, err)
		}
		if n > 0 {
			return c.table + "." + c.name, nil
		}
	}
	return "", nil
}

// CompleteRotation finishes a rotation that was committed but not
// installed: when the pending secret's ring matches the key identifier
// in the database, it becomes DATA_DIR/secret_key. It only ever moves
// forward, so it is safe without the Go lock while a rotation runs; it
// reports whether it installed the secret. keyID reads the stored key
// identifier; it is called only when a pending secret exists.
func CompleteRotation(dataDir string, material func() ([]byte, error), keyID func() (string, error)) (bool, error) {
	pending := filepath.Join(dataDir, keyring.GoDirName, PendingSecretName)
	secret, err := readSecretFile(pending)
	if err != nil || secret == nil {
		return false, err
	}
	m, err := material()
	if err != nil {
		return false, err
	}
	ring, err := keyring.Open(secret, m)
	if err != nil {
		return false, err
	}
	stored, err := keyID()
	if err != nil {
		return false, err
	}
	if stored != ring.KeyID() {
		return false, nil
	}
	if err := finishRotation(dataDir, secret, func() {}); err != nil {
		return false, fmt.Errorf("backup: complete the secret rotation: %w", err)
	}
	return true, nil
}

// DiscardStaleRotation removes the pending secret of a rotation that did
// not commit: the database is still under ring. The caller holds the Go
// lock, so no rotation is running.
func DiscardStaleRotation(dataDir string, ring *keyring.Ring, storedKeyID string) error {
	pending := filepath.Join(dataDir, keyring.GoDirName, PendingSecretName)
	secret, err := readSecretFile(pending)
	if err != nil || secret == nil {
		return err
	}
	if ring.Verify(storedKeyID) != nil {
		return nil
	}
	return removeRegular(pending)
}
