package backup

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/store"
)

// resealProbe is the rotation step of vault_probe.
var resealProbe = RotationStep{Name: "probe", Run: func(ctx context.Context, tx *store.Tx, rt *keyring.Rotation) (int, error) {
	var sealed []byte
	if err := tx.QueryRowContext(ctx, `SELECT sealed FROM vault_probe WHERE id = '1'`).Scan(&sealed); err != nil {
		return 0, err
	}
	out, err := rt.Reseal(keyring.SSHKey, probeAAD(), sealed)
	if err != nil {
		return 0, err
	}
	_, err = tx.ExecContext(ctx, `UPDATE vault_probe SET sealed = ? WHERE id = '1'`, out)
	return 1, err
}}

// keepInstallation is a file-secret installation beside legacy data
// (KeepSecret) that knows vault_probe.
func keepInstallation(t *testing.T, steps ...RotationStep) *Installation {
	t.Helper()
	in := fileInstallation(t)
	in.KeepSecret, in.Reseal = true, steps
	in.Schemas = append(in.Schemas, probeSchema)
	in.Probes = []Probe{probe}
	return in
}

// sealedArchive is an archive of host A (hostASecret, its own material)
// with a mark and one sealed record.
func sealedArchive(t *testing.T) string {
	t.Helper()
	return sealedArchiveWith(t, hostASecret)
}

// sealedArchiveWith is sealedArchive made with secret and other material.
func sealedArchiveWith(t *testing.T, secret []byte) string {
	t.Helper()
	dir := t.TempDir()
	material := bytes.Repeat([]byte{0x5a}, keyring.MaterialSize)
	ring, err := keyring.Open(secret, material)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "src.db")
	db, err := store.Open(t.Context(), path, store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := ring.Seal(keyring.SSHKey, probeAAD(), []byte("private key"))
	if err == nil {
		err = db.ApplyAll(t.Context(), markSchema, probeSchema)
	}
	if err == nil {
		err = db.Write(t.Context(), func(tx *store.Tx) error {
			if _, err := tx.ExecContext(t.Context(), `INSERT INTO hosts_marks VALUES ('restored')`); err != nil {
				return err
			}
			_, err := tx.ExecContext(t.Context(), `INSERT INTO vault_probe VALUES ('1', ?)`, sealed)
			return err
		})
	}
	if err := errors.Join(err, db.CloseForActivation(t.Context())); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(dir, "a.tar")
	if err := WriteFile(archive, Contents{Database: path, SecretKey: secret, Material: material, KeyID: ring.KeyID(),
		Reason: ReasonPurge, Now: time.Now()}); err != nil {
		t.Fatal(err)
	}
	return archive
}

func fileBytes(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path) // #nosec G304 -- test data
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// Beside legacy data a Go archive of another SECRET_KEY is resealed
// under the active ring: DATA_DIR/secret_key and the material stay byte
// for byte, the restored database carries the active key identifier and
// its sealed record opens under the active ring only.
func TestRestoreBesideLegacyDataResealsUnderTheActiveKey(t *testing.T) {
	t.Parallel()
	in := keepInstallation(t, resealProbe)
	secretFile := filepath.Join(in.DataDir, secretFileName)
	secretBefore, materialBefore := fileBytes(t, secretFile), fileBytes(t, in.MaterialPath)
	active, err := keyring.Open(in.SecretKey, in.Material)
	if err != nil {
		t.Fatal(err)
	}
	st, err := Stage(t.Context(), in, StageRequest{OperationID: "keep", Archive: sealedArchive(t)})
	if err != nil {
		t.Fatal(err)
	}
	if st.Secret || st.Material != "" || st.KeyID != active.KeyID() {
		t.Fatalf("staged %+v, want the active key %s without secret or material", st, active.KeyID())
	}
	goDir := filepath.Join(in.DataDir, keyring.GoDirName)
	if err := Commit(goDir, st, in, time.Now()); err != nil {
		t.Fatal(err)
	}
	if j, err := Activate(in.DataDir, time.Now); err != nil || j.State != RestoreSucceeded {
		t.Fatalf("%+v, %v", j, err)
	}
	if !bytes.Equal(fileBytes(t, secretFile), secretBefore) || !bytes.Equal(fileBytes(t, in.MaterialPath), materialBefore) {
		t.Fatal("the restore changed DATA_DIR/secret_key or the keyring material")
	}
	dbPath := filepath.Join(goDir, keyring.DatabaseName)
	if got := marks(t, dbPath); len(got) != 2 || got[0] != "restored" || got[1] != "prepared:"+active.KeyID() {
		t.Fatalf("database after restore: %v", got)
	}
	db, err := store.Open(t.Context(), dbPath, store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	err = db.Read(t.Context(), func(tx *store.Tx) error {
		ok, err := probe(t.Context(), tx, active)
		if !ok || err != nil {
			return errors.Join(errors.New("the record does not open under the active ring"), err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	assertNoLeftovers(t, in.DataDir)
}

// A capability whose records the steps miss stops the staging before
// anything changes; so does an installation without steps.
func TestRestoreResealRefusesLeftovers(t *testing.T) {
	t.Parallel()
	for name, steps := range map[string][]RotationStep{
		"missing step": {{Name: "nothing", Run: func(context.Context, *store.Tx, *keyring.Rotation) (int, error) { return 0, nil }}},
		"no steps":     nil,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			in := keepInstallation(t, steps...)
			secretBefore := fileBytes(t, filepath.Join(in.DataDir, secretFileName))
			_, err := Stage(t.Context(), in, StageRequest{OperationID: "left", Archive: sealedArchive(t)})
			if err == nil || (steps != nil && !errors.Is(err, ErrRotationLeftover)) {
				t.Fatalf("got %v", err)
			}
			assertNoLeftovers(t, in.DataDir)
			if !bytes.Equal(fileBytes(t, filepath.Join(in.DataDir, secretFileName)), secretBefore) {
				t.Fatal("DATA_DIR/secret_key changed")
			}
			if got := marks(t, filepath.Join(in.DataDir, keyring.GoDirName, keyring.DatabaseName)); len(got) != 1 || got[0] != "live" {
				t.Fatalf("live database: %v", got)
			}
		})
	}
}
