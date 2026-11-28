package main

import (
	"path/filepath"
	"testing"

	"github.com/bifrost0x/webssh/internal/backup"
	"github.com/bifrost0x/webssh/internal/config"
	"github.com/bifrost0x/webssh/internal/keyring"
)

// While the 3.3 data exists, DATA_DIR/secret_key is in every Python
// export of the way back. An archive made with --without-secret-key then
// leaves out the keyring material as well: together with such a Python
// export it would open every sealed secret (migration specification 2.2).
// The archive restores on the same host, which keeps its material.
func TestWithoutSecretKeyBesideLegacyDataLeavesOutTheMaterial(t *testing.T) {
	dir := migratedBesideLegacy(t)
	archive := filepath.Join(t.TempDir(), "without.tar")
	if out := runCLI(t, "backup", "create", "--destination", archive, "--without-secret-key", "--confirm-offline"); out.Code != 0 {
		t.Fatalf("create: %+v", out)
	}
	m := archiveMembers(t, archive)
	if m["data/secret_key"] || m[backup.MaterialName] {
		t.Fatalf("members of a --without-secret-key archive beside the 3.3 data: %v", m)
	}
	_, material, err := keyring.MaterialLocation(dir, true)
	if err != nil || material == nil {
		t.Fatalf("material of the host: %v", err)
	}
	if _, err := backup.VerifyWith(t.Context(), archive, backup.VerifyOptions{Secret: []byte(readSecret(t, dir)), Material: material}); err != nil {
		t.Fatalf("verify with the host's secret and material: %v", err)
	}
	if _, err := backup.VerifyWith(t.Context(), archive, backup.VerifyOptions{Secret: []byte(readSecret(t, dir))}); err == nil {
		t.Fatal("the archive opened without the host's material")
	}
	if out := runCLI(t, "backup", "restore", archive, "--confirm-offline"); out.Code != 0 {
		t.Fatalf("restore on the same host: %+v", out)
	}

	// With the secret in the archive, or once the 3.3 data is gone, the
	// material stays in so a lost volume can be restored.
	with := filepath.Join(t.TempDir(), "with.tar")
	if out := runCLI(t, "backup", "create", "--destination", with, "--confirm-offline"); out.Code != 0 {
		t.Fatalf("create with the secret: %+v", out)
	}
	if m := archiveMembers(t, with); !m["data/secret_key"] || !m[backup.MaterialName] {
		t.Fatalf("members of a full archive: %v", m)
	}
}

func TestWithoutSecretKeyAfterThePurgeKeepsTheMaterial(t *testing.T) {
	migratedPurged(t)
	archive := filepath.Join(t.TempDir(), "without.tar")
	if out := runCLI(t, "backup", "create", "--destination", archive, "--without-secret-key", "--confirm-offline"); out.Code != 0 {
		t.Fatalf("create: %+v", out)
	}
	if m := archiveMembers(t, archive); m["data/secret_key"] || !m[backup.MaterialName] {
		t.Fatalf("members of a --without-secret-key archive without 3.3 data: %v", m)
	}
}

// With SECRET_KEY from the environment the Python export never holds the
// key, so the material stays in the archive even beside the 3.3 data.
func TestLeaveOutMaterialOnlyForAFileSecretBesideLegacyData(t *testing.T) {
	if !leaveOutMaterial(config.SecretFromFile, true, true) {
		t.Fatal("a file secret left out beside the 3.3 data keeps the material")
	}
	for _, c := range []struct {
		name               string
		source             config.SecretSource
		omitSecret, legacy bool
	}{
		{"environment secret", config.SecretFromEnvironment, true, true},
		{"secret included", config.SecretFromFile, false, true},
		{"no legacy data", config.SecretFromFile, true, false},
	} {
		if leaveOutMaterial(c.source, c.omitSecret, c.legacy) {
			t.Errorf("%s: material left out", c.name)
		}
	}
}
