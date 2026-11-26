package legacy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/store"
)

// presence classifies the legacy source of a DATA_DIR.
type presence int

const (
	legacyNone presence = iota
	legacyPartial
	legacyComplete
)

// legacyIndicators are legacy source paths other than app.db. DATA_DIR/
// secret_key is not one: Go writes it on a new installation too (I-08).
var legacyIndicators = []string{
	"users", "deleted_users", "app_settings.json", "known_hosts", "session_epoch", "recovery-check.json",
	"profiles.json", "keys", "commands", "app.db-journal", "app.db-wal",
}

func legacyPresence(dataDir string) (presence, error) {
	info, err := os.Lstat(filepath.Join(dataDir, "app.db"))
	switch {
	case err == nil && info.Mode().IsRegular():
		return legacyComplete, nil
	case err == nil:
		return legacyNone, fmt.Errorf("%w: app.db", ErrUnsafePath)
	case !errors.Is(err, fs.ErrNotExist):
		return legacyNone, fmt.Errorf("legacy: inspect app.db: %w", err)
	}
	for _, name := range legacyIndicators {
		found, err := holdsData(filepath.Join(dataDir, name))
		if err != nil {
			return legacyNone, err
		}
		if found {
			return legacyPartial, nil
		}
	}
	return legacyNone, nil
}

// holdsData reports whether path is anything but a missing path or a tree
// of directories only. Empty directories are no legacy data: the
// entrypoint and platform.PrepareDataDir create logs/ and keys/ on every
// start. The walk does not follow links; a link counts as data.
func holdsData(path string) (bool, error) {
	info, err := os.Lstat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("legacy: inspect %s: %w", path, err)
	case !info.IsDir():
		return true, nil
	}
	found := false
	err = filepath.WalkDir(path, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			found = true
			return fs.SkipAll
		}
		return nil
	})
	if err != nil {
		return false, fmt.Errorf("legacy: inspect %s: %w", path, err)
	}
	return found, nil
}

// evaluation is the result of the state evaluation of section 5.1.
type evaluation struct {
	state    State
	legacy   presence
	dbExists bool
	record   *Record
	keyID    string
	marker   *Marker
	// stop is set for the states that do not start (S1a, S3, S7, S9).
	stop     *StopError
	warnings []Warning
}

// evaluate decides the state of a DATA_DIR. The caller holds the Go lock
// and has removed leftover staging directories (S6). Besides reading, it
// only moves keyring material that reached go/ beside legacy data into
// logs/.webssh-go/ (section 2.2): nothing may start before that, because a
// Python export would then carry decryptable secrets.
func evaluate(ctx context.Context, l layout, secret string) (evaluation, error) {
	var ev evaluation
	var err error
	if ev.legacy, err = legacyPresence(l.dataDir); err != nil {
		ev.state, ev.stop = S7, stop(S7, CodeUnsafeSource, "the legacy source cannot be inspected safely", err)
		return ev, nil
	}
	if ev.dbExists, err = l.databasePresent(); err != nil {
		ev.state, ev.stop = S7, stop(S7, CodeGoDatabase, "the Go directory holds something other than a regular database file", err)
		return ev, nil
	}
	if ev.marker, err = readMarker(l); err != nil {
		return ev, err
	}
	if ev.dbExists {
		if ev.record, ev.keyID, err = inspectDatabase(ctx, l.database); err != nil {
			ev.state, ev.stop = S7, stop(S7, CodeGoDatabase, "the Go database "+l.database+
				" does not open or fails its integrity check; it is never replaced automatically. Restore it from a backup", err)
			return ev, nil
		}
	}
	if s := ev.checkMaterial(l, secret); s != nil {
		ev.state, ev.stop = S9, s
		return ev, nil
	}
	switch {
	case !ev.dbExists && ev.legacy == legacyComplete && ev.marker != nil:
		msg := fmt.Sprintf("Go data existed (database %s, migrated %s) and is missing, for example after a Python "+
			"restore or a move of the data directory; run `webssh migrate --replace` to migrate again from the legacy "+
			"data", ev.marker.DatabaseID, ev.marker.MigratedAt)
		if kept := l.replacedDatabases(); len(kept) > 0 {
			msg += "; databases kept by an earlier replacement: " + strings.Join(kept, ", ")
		}
		ev.state, ev.stop = S1a, stop(S1a, CodeGoDataMissing, msg, nil)
	case !ev.dbExists && ev.legacy == legacyComplete:
		ev.state = S1
	case !ev.dbExists && ev.legacy == legacyPartial:
		ev.state, ev.stop = S7, stop(S7, CodeLegacyUnknown, "the data directory holds Python data without app.db; "+
			"Go does not migrate a partial legacy source", nil)
	case !ev.dbExists && ev.marker != nil:
		ev.state, ev.stop = S7, stop(S7, CodeGoDataMissing, "the marker "+l.marker+" says Go data existed, but neither the "+
			"Go database nor legacy data is present; restore the data directory from a backup", nil)
	case !ev.dbExists:
		ev.state = S0
	case ev.record == nil && ev.legacy != legacyNone:
		ev.state, ev.stop = S7, stop(S7, CodeGoDatabase, "the Go database has no completed migration record, but legacy "+
			"data is present; this is not the result of an interrupted migration", nil)
	case ev.record == nil:
		ev.state = S2 // a Go-native installation
	case ev.legacy == legacyNone:
		ev.state = S5
		ev.warnings = append(ev.warnings, Warning{Code: "legacy_missing", Message: "the legacy data is gone without " +
			"`webssh legacy purge`; the way back to the Python release no longer exists"})
	default:
		ev.state, err = ev.compareSource(l)
		if err != nil {
			return ev, err
		}
	}
	return ev, nil
}

// compareSource is the validity rule: S2 when the digest of the legacy
// source equals the recorded one, S3 otherwise.
func (ev *evaluation) compareSource(l layout) (State, error) {
	listing, err := scanSource(l.dataDir, ev.record.Listing, ev.record.ScannedAt)
	if err != nil {
		return "", stop(S3, CodeLegacyChanged, "the legacy source could not be read", err)
	}
	if listing.Digest() == ev.record.SourceDigest {
		return S2, nil
	}
	ev.stop = stop(S3, CodeLegacyChanged, "the legacy data changed since the migration (for example because the Python "+
		"release ran again). Run `webssh migrate --replace` to migrate the current legacy data; the changes made in Go "+
		"since the migration are then replaced (the replaced database is kept in the Go directory). To remove legacy "+
		"data on purpose, `webssh legacy purge` is the supported way", nil)
	return S3, nil
}

// checkMaterial is state S9, and the move of material out of go/ while
// legacy data exists. It returns nil when the material is usable or no
// database needs it.
func (ev *evaluation) checkMaterial(l layout, secret string) *StopError {
	inGo := filepath.Join(l.goDir, keyring.MaterialName)
	_, goErr := os.Lstat(inGo)
	needCheck := ev.dbExists && ev.keyID != ""
	moveOut := ev.legacy != legacyNone && goErr == nil
	if !needCheck && !moveOut {
		return nil
	}
	material, err := keyring.LoadOrCreateMaterial(l.dataDir, ev.legacy != legacyNone)
	if err != nil {
		return stop(S9, CodeKeyMaterial, "the keyring material cannot be used", err)
	}
	ring, err := keyring.Open([]byte(secret), material)
	if err == nil && needCheck {
		err = ring.Verify(ev.keyID)
	}
	if err != nil {
		return stop(S9, CodeKeyMaterial, "SECRET_KEY and the keyring material do not match the Go database: sealed SSH keys, "+
			"saved passwords and second factors cannot be read. Restore logs/.webssh-go/keyring-material from the volume "+
			"backup, or run `webssh migrate --replace` while the legacy data exists", err)
	}
	if !moveOut {
		return nil
	}
	moved, err := keyring.MoveMaterialToState(l.dataDir, ring, ev.keyID)
	if err != nil {
		return stop(S9, CodeKeyMaterial, "the keyring material in go/ could not be moved to logs/.webssh-go/", err)
	}
	if moved {
		ev.warnings = append(ev.warnings, Warning{Code: "keyring_material_moved", Message: "the keyring material was in go/ " +
			"beside legacy data and was moved to logs/.webssh-go/, so that Python exports do not carry it"})
	}
	return nil
}

// inspectDatabase opens the Go database without changing it where
// possible, runs quick_check and reads the record and the key identifier.
// A database Go closed cleanly is in rollback-journal mode and is opened
// read-only; one left in WAL mode by a crash is opened normally, so that
// SQLite recovers its own WAL.
func inspectDatabase(ctx context.Context, path string) (*Record, string, error) {
	wal, err := walMode(path)
	if err != nil {
		return nil, "", err
	}
	if wal {
		db, err := store.Open(ctx, path, store.Options{})
		if err != nil {
			return nil, "", err
		}
		var rec *Record
		var keyID string
		err = db.QuickCheck(ctx)
		if err == nil {
			err = db.Read(ctx, func(tx *store.Tx) error {
				var err error
				if rec, err = readRecord(ctx, tx); err == nil {
					keyID, err = readKeyID(ctx, tx)
				}
				return err
			})
		}
		return rec, keyID, errors.Join(err, db.Close())
	}
	db, err := store.OpenReadOnly(ctx, path, store.Shared)
	if err != nil {
		return nil, "", err
	}
	defer db.Close()
	var result string
	if err := db.QueryRowContext(ctx, "PRAGMA quick_check").Scan(&result); err != nil || result != "ok" {
		return nil, "", errors.Join(store.ErrCorrupt, err)
	}
	rec, err := readRecord(ctx, db)
	if err != nil {
		return nil, "", err
	}
	keyID, err := readKeyID(ctx, db)
	return rec, keyID, err
}

// walMode reports whether the database header says WAL. A file that is
// shorter than a header or not SQLite is an error.
func walMode(path string) (bool, error) {
	f, err := os.Open(path) // #nosec G304 -- the Go database
	if err != nil {
		return false, err
	}
	defer f.Close()
	header := make([]byte, sqliteHeaderSize)
	if _, err := io.ReadFull(f, header); err != nil || string(header[:16]) != "SQLite format 3\x00" {
		return false, fmt.Errorf("%w: not an SQLite database", store.ErrCorrupt)
	}
	return header[18] == 2 && header[19] == 2, nil
}
