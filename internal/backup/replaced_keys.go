package backup

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/bifrost0x/webssh/internal/keyring"
)

const (
	// replacedPrefix names the directories `migrate --replace` keeps in
	// the Go directory (internal/migrate/legacy).
	replacedPrefix = "replaced-"
	// keptMaterialName and keptSecretName hold, beside the data of such a
	// directory, the keys it opens with once a restore has installed
	// others.
	keptMaterialName = "keyring-material"
	keptSecretName   = "secret_key"
)

// keepReplacedKeys runs before a restore that installs other material or
// another SECRET_KEY on an installation without legacy data. The archives
// and databases `migrate --replace` kept hold neither (I-22) and open only
// with the installation's current keys; without a copy beside them they
// would be lost with the previous keys, which the activation removes. A
// directory that already holds key material of its own is left alone.
func keepReplacedKeys(in *Installation, secretChanges bool) error {
	dirs, err := filepath.Glob(filepath.Join(in.goDir(), replacedPrefix+"*"))
	if err != nil {
		return err
	}
	for _, dir := range dirs {
		need, err := needsKeys(dir)
		if err != nil {
			return fmt.Errorf("backup: inspect %s: %w", dir, err)
		}
		if !need {
			continue
		}
		if err := writePrivate(filepath.Join(dir, keptMaterialName), in.Material); err != nil {
			return fmt.Errorf("backup: keep the material for %s: %w", dir, err)
		}
		if secretChanges && !exists(filepath.Join(dir, keptSecretName)) {
			if err := writePrivate(filepath.Join(dir, keptSecretName), in.SecretKey); err != nil {
				return fmt.Errorf("backup: keep SECRET_KEY for %s: %w", dir, err)
			}
		}
	}
	return nil
}

// needsKeys reports a replaced directory with a Go backup or a database
// and no key material of its own.
func needsKeys(dir string) (bool, error) {
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() {
		return false, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false, err
	}
	data := false
	for _, e := range entries {
		name := e.Name()
		switch {
		case strings.HasPrefix(name, keptMaterialName):
			return false, nil
		case !e.Type().IsRegular():
		case name == keyring.DatabaseName, strings.HasPrefix(name, "webssh-backup-") && strings.HasSuffix(name, ".tar"):
			data = true
		}
	}
	return data, nil
}
