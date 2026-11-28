package backup

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/store"
)

// Beside legacy data an archive with the same SECRET_KEY but other
// material (another host with the same environment secret, a clone) is
// resealed like one of another SECRET_KEY: the material stays byte for
// byte and the record opens under the active ring.
func TestRestoreBesideLegacyDataKeepsTheMaterialForTheSameSecret(t *testing.T) {
	t.Parallel()
	in := keepInstallation(t, resealProbe)
	materialBefore := fileBytes(t, in.MaterialPath)
	active, err := keyring.Open(in.SecretKey, in.Material)
	if err != nil {
		t.Fatal(err)
	}
	st, err := Stage(t.Context(), in, StageRequest{OperationID: "same", Archive: sealedArchiveWith(t, in.SecretKey)})
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
	if !bytes.Equal(fileBytes(t, in.MaterialPath), materialBefore) {
		t.Fatal("the restore rewrote the keyring material beside legacy data")
	}
	db, err := store.Open(t.Context(), filepath.Join(goDir, keyring.DatabaseName), store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Read(t.Context(), func(tx *store.Tx) error {
		ok, err := probe(t.Context(), tx, active)
		if !ok || err != nil {
			return errors.Join(errors.New("the record does not open under the active ring"), err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// The archives `migrate --replace` keeps in go/replaced-<UTC>/ hold
// neither SECRET_KEY nor material. A restore that installs other material
// or another SECRET_KEY keeps the previous ones beside them, so they still
// open afterwards.
func TestRestoreKeepsTheKeysOfReplacedArchives(t *testing.T) {
	t.Parallel()
	for name, adopt := range map[string]bool{"other material": false, "other secret": true} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			in := installation(t, testSecret, "live")
			if adopt {
				in = fileInstallation(t)
			}
			goDir := filepath.Join(in.DataDir, keyring.GoDirName)
			ring, err := keyring.Open(in.SecretKey, in.Material)
			if err != nil {
				t.Fatal(err)
			}
			replaced := filepath.Join(goDir, "replaced-20261101T000000Z")
			if err := os.Mkdir(replaced, 0o700); err != nil {
				t.Fatal(err)
			}
			archive := filepath.Join(replaced, ArchiveName(time.Now()))
			if err := WriteFile(archive, Contents{Database: filepath.Join(goDir, keyring.DatabaseName), KeyID: ring.KeyID(),
				Reason: ReasonReplaced, Now: time.Now()}); err != nil {
				t.Fatal(err)
			}
			oldSecret, oldMaterial := bytes.Clone(in.SecretKey), bytes.Clone(in.Material)
			if adopt {
				stageHostA(t, in, "op1")
			} else {
				stageForeign(t, in, "op1")
			}
			if j, err := Activate(in.DataDir, time.Now); err != nil || j.State != RestoreSucceeded {
				t.Fatalf("%+v, %v", j, err)
			}
			kept := fileBytes(t, filepath.Join(replaced, keptMaterialName))
			if !bytes.Equal(kept, oldMaterial) {
				t.Fatal("the previous material is not kept beside the replaced archive")
			}
			secret := oldSecret
			if adopt {
				secret = fileBytes(t, filepath.Join(replaced, keptSecretName))
				if !bytes.Equal(secret, oldSecret) {
					t.Fatal("the previous SECRET_KEY is not kept beside the replaced archive")
				}
			}
			if _, err := VerifyWith(t.Context(), archive, VerifyOptions{Secret: secret, Material: kept}); err != nil {
				t.Fatalf("the replaced archive does not open with the kept keys: %v", err)
			}
		})
	}
}
