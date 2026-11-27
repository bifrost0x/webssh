package backup

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/keyring"
)

var hostASecret = []byte("host-a-secret-0123456789abcdef0123")

// fileInstallation is an installation whose SECRET_KEY is in
// DATA_DIR/secret_key (AdoptSecret).
func fileInstallation(t *testing.T) *Installation {
	t.Helper()
	in := installation(t, testSecret, "live")
	in.AdoptSecret = true
	if err := installSecretFile(filepath.Join(in.DataDir, secretFileName), testSecret); err != nil {
		t.Fatal(err)
	}
	return in
}

func stageHostA(t *testing.T, in *Installation, id string) (Staged, []byte, string) {
	t.Helper()
	archive, material, keyID := foreignArchive(t, hostASecret, "restored", ReasonPurge)
	st, err := Stage(t.Context(), in, StageRequest{OperationID: id, Archive: archive})
	if err != nil {
		t.Fatal(err)
	}
	if !st.Secret || st.KeyID != keyID {
		t.Fatalf("staged %+v", st)
	}
	if got, _ := readSecretFile(filepath.Join(in.DataDir, secretFileName)); string(got) != string(testSecret) {
		t.Fatal("staging changed DATA_DIR/secret_key")
	}
	if err := Commit(filepath.Join(in.DataDir, keyring.GoDirName), st, in, time.Now()); err != nil {
		t.Fatal(err)
	}
	return st, material, keyID
}

func secretOf(t *testing.T, in *Installation) string {
	t.Helper()
	got, err := readSecretFile(filepath.Join(in.DataDir, secretFileName))
	if err != nil {
		t.Fatal(err)
	}
	return string(got)
}

// A Go archive of another host brings its SECRET_KEY when the
// installation keeps its own in DATA_DIR/secret_key, at every crash point
// of the activation; the next start reads the archive's secret.
func TestRestoreAdoptsTheArchiveSecret(t *testing.T) {
	t.Parallel()
	points := []string{PointPreviousKept, PointDatabaseRenamed, PointPreviousMaterial, PointMaterialInstalled,
		PointPreviousSecret, PointSecretInstalled, PointJournalDone}
	for _, p := range append([]string{""}, points...) {
		t.Run("crash at "+p, func(t *testing.T) {
			t.Parallel()
			in := fileInstallation(t)
			_, material, keyID := stageHostA(t, in, "adopt")
			if p != "" {
				crashed := func() (crash bool) {
					defer func() { crash = recover() != nil }()
					_, _ = activate(in.DataDir, time.Now, func(at string) {
						if at == p {
							panic("crash")
						}
					})
					return false
				}()
				if !crashed {
					t.Fatalf("checkpoint %s not reached", p)
				}
			}
			j, err := Activate(in.DataDir, time.Now)
			if err != nil || j.State != RestoreSucceeded {
				t.Fatalf("%+v, %v", j, err)
			}
			assertRestored(t, in, material, keyID)
			if secretOf(t, in) != string(hostASecret) {
				t.Fatal("DATA_DIR/secret_key is not the archive's SECRET_KEY")
			}
		})
	}
}

// A failing activation puts the previous SECRET_KEY back with the
// database and the material.
func TestFailedActivationKeepsTheSecret(t *testing.T) {
	t.Parallel()
	in := fileInstallation(t)
	st, _, _ := stageHostA(t, in, "broken")
	// The staged secret is damaged after Commit.
	if err := os.WriteFile(filepath.Join(st.Dir, stagedSecretName), []byte("a\nb\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	j, err := Activate(in.DataDir, time.Now)
	if err == nil || j.State != RestoreFailed {
		t.Fatalf("%+v, %v", j, err)
	}
	if secretOf(t, in) != string(testSecret) {
		t.Fatal("the rollback did not keep DATA_DIR/secret_key")
	}
	if got := marks(t, filepath.Join(in.DataDir, keyring.GoDirName, keyring.DatabaseName)); len(got) != 1 || got[0] != "live" {
		t.Fatalf("database after rollback: %v", got)
	}
	assertNoLeftovers(t, in.DataDir)
}

// With SECRET_KEY from the environment an archive of another key is
// refused and nothing is staged; an archive of the same key needs no
// secret change.
func TestRestoreWithEnvironmentSecretRefusesAnotherKey(t *testing.T) {
	t.Parallel()
	in := installation(t, testSecret, "live")
	in.EnvironmentSecret = true
	archive, _, _ := foreignArchive(t, hostASecret, "restored", ReasonPurge)
	_, err := Stage(t.Context(), in, StageRequest{OperationID: "env", Archive: archive})
	if !errors.Is(err, ErrSecretMismatch) {
		t.Fatalf("got %v", err)
	}
	assertNoLeftovers(t, in.DataDir)
	in = fileInstallation(t)
	archive, _, _ = foreignArchive(t, testSecret, "restored", ReasonPurge)
	st, err := Stage(t.Context(), in, StageRequest{OperationID: "same", Archive: archive})
	if err != nil || st.Secret {
		t.Fatalf("same key: %+v, %v", st, err)
	}
	if _, err := Inspect(t.Context(), in, archive); err != nil {
		t.Fatalf("inspect: %v", err)
	}
}
