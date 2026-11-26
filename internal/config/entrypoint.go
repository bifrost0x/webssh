package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// legacySecretKeyFile is the secret file of installations from before
// DATA_DIR could be moved; entrypoint.sh refuses to start when it
// disagrees with the one in DATA_DIR.
const legacySecretKeyFile = "/app/data/secret_key" // #nosec G101 -- a file location, not a credential

// maxExportedSecret is the longest SECRET_KEY entrypoint.sh can pass to the
// Python process: Linux limits one environment string, "SECRET_KEY=" and
// the terminating NUL included, to 131072 bytes (MAX_ARG_STRLEN).
const maxExportedSecret = 131072 - len("SECRET_KEY=") - 1

// ResolveDataDir applies the DATA_DIR rule of entrypoint.sh: the default
// is /app/data, a relative path is refused, and the path is resolved with
// Python's os.path.realpath, which keeps parts that do not exist yet.
func ResolveDataDir(lookup LookupFunc) (string, error) {
	return resolveDataDir(osFS{}, lookup)
}

func resolveDataDir(fsys fileSystem, lookup LookupFunc) (string, error) {
	dir, _ := lookup("DATA_DIR")
	if dir == "" {
		dir = defaultDataDir
	}
	if !strings.HasPrefix(dir, "/") {
		return "", configError("DATA_DIR", "DATA_DIR must be an absolute path.")
	}
	// The shell reads the result through $(...), which drops trailing line
	// feeds.
	return strings.TrimRight(pyRealpath(fsys, dir), "\n"), nil
}

// SecretResolution is the application secret as entrypoint.sh resolves it.
type SecretResolution struct {
	Key    Secret
	Source SecretSource
	// File is DATA_DIR/secret_key.
	File string
	// Generated is true when the secret was created and written to File.
	Generated bool
}

// ResolveSecretKey applies the SECRET_KEY rule of entrypoint.sh to the
// prepared data directory: a SECRET_KEY that is not a placeholder wins;
// otherwise DATA_DIR/secret_key is read, or created with a new random
// secret. Load then applies the checks of config.py to the result.
func ResolveSecretKey(dataDir string, lookup LookupFunc) (SecretResolution, []Warning, error) {
	return resolveSecretKey(osFS{}, createSecretFile, legacySecretKeyFile, dataDir, lookup)
}

// entrypointPlaceholder is the placeholder test of entrypoint.sh: lower
// case (ASCII, as tr does) and every ASCII white space removed.
func entrypointPlaceholder(v string) bool {
	norm := strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\n', '\v', '\f', '\r':
			return -1
		}
		if r >= 'A' && r <= 'Z' {
			return r + 'a' - 'A'
		}
		return r
	}, v)
	return norm == "" || secretPlaceholders[norm]
}

func resolveSecretKey(fsys fileSystem, create func(path string, data []byte) error, legacy, dataDir string, lookup LookupFunc) (SecretResolution, []Warning, error) {
	var warns []Warning
	env, _ := lookup("SECRET_KEY")
	file := dataDir + "/secret_key"
	if !entrypointPlaceholder(env) {
		return SecretResolution{Key: NewSecret([]byte(env)), Source: SecretFromEnvironment, File: file}, nil, nil
	}
	if env != "" {
		warns = append(warns, Warning{Kind: WarnSecret, Variable: "SECRET_KEY", Message: "the value is a placeholder and counts as not set; the secret in " + file + " is used"})
	}
	res := SecretResolution{Source: SecretFromFile, File: file}
	if file != legacy && isRegularFile(fsys, legacy) {
		if !isRegularFile(fsys, file) {
			return res, warns, configError("DATA_DIR", fmt.Sprintf("a legacy secret exists at %s but DATA_DIR is %s. Copy that file to %s with mode 600 before starting WebSSH.", legacy, dataDir, file))
		}
		a, errA := readSecretFile(fsys, legacy)
		b, errB := readSecretFile(fsys, file)
		if errA != nil || errB != nil || !bytes.Equal(a, b) {
			return res, warns, configError("DATA_DIR", "conflicting secret_key files exist under /app/data and DATA_DIR.")
		}
	}
	if isRegularFile(fsys, file) {
		raw, err := readSecretFile(fsys, file)
		if err != nil {
			return res, warns, fmt.Errorf("config: read %s: %w", file, err)
		}
		// $(cat file) drops NUL bytes and every trailing line feed; a
		// carriage return stays part of the secret.
		key := bytes.TrimRight(bytes.ReplaceAll(raw, []byte{0}, nil), "\n")
		if len(key) > maxExportedSecret {
			return res, warns, configError("SECRET_KEY", file+" is too large to be used as SECRET_KEY")
		}
		res.Key = NewSecret(key)
		warns = append(warns, Warning{Kind: WarnSecret, Message: "Loaded persisted SECRET_KEY from " + file})
		return res, warns, nil
	}
	key, err := randomSecret()
	if err != nil {
		return res, warns, fmt.Errorf("config: generate SECRET_KEY: %w", err)
	}
	if err := create(file, []byte(key+"\n")); err != nil {
		return res, warns, configError("SECRET_KEY", fmt.Sprintf("could not write %s -- mount a writable volume on %s.", file, dataDir))
	}
	res.Key, res.Generated = NewSecret([]byte(key)), true
	warns = append(warns, Warning{Kind: WarnSecret, Message: "Generated a new SECRET_KEY and persisted it to " + file + ". Keep " + dataDir + " on a volume so it survives container re-creation."})
	if existing := existingData(fsys, dataDir); existing != "" {
		warns = append(warns, Warning{Kind: WarnSecret, Variable: "SECRET_KEY", Message: "a new secret was generated although " + existing + " exists; data encrypted with the previous secret cannot be read"})
	}
	return res, warns, nil
}

// isRegularFile is the shell test [ -f path ]: the path, links followed,
// is a regular file.
func isRegularFile(fsys fileSystem, path string) bool {
	info, err := fsys.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

func readSecretFile(fsys fileSystem, path string) ([]byte, error) {
	return fsys.ReadFile(path)
}

func existingData(fsys fileSystem, dataDir string) string {
	for _, name := range []string{"app.db", "go"} {
		p := filepath.Join(dataDir, name)
		if _, err := fsys.Lstat(p); err == nil {
			return p
		}
	}
	return ""
}

// createSecretFile publishes a new secret file with mode 0600. The
// content is written and synced under a temporary name first and then
// linked to path, so no process ever reads a partial secret; the link
// fails if path exists in any form, so nothing is replaced and no link is
// followed (the shell redirection of entrypoint.sh did both).
func createSecretFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".secret_key-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(0o600); err != nil {
		return errors.Join(err, tmp.Close())
	}
	if _, err := io.Copy(tmp, bytes.NewReader(data)); err != nil {
		return errors.Join(err, tmp.Close())
	}
	if err := tmp.Sync(); err != nil {
		return errors.Join(err, tmp.Close())
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Link(tmpName, path); err != nil {
		return err
	}
	return syncDir(dir)
}

func syncDir(dir string) (err error) {
	d, err := os.Open(dir) // #nosec G304 -- DATA_DIR
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, d.Close()) }()
	return d.Sync()
}

// Overlay returns the environment as entrypoint.sh hands it to the Python
// process: DATA_DIR resolved, SECRET_KEY taken from the file when it came
// from there, and WEBSSH_SECRET_KEY_SOURCE set.
func (r SecretResolution) Overlay(dataDir string, lookup LookupFunc) LookupFunc {
	return func(name string) (string, bool) {
		switch name {
		case "DATA_DIR":
			return dataDir, true
		case secretSourceVariable:
			return string(r.Source), true
		case "SECRET_KEY":
			if r.Source == SecretFromFile {
				return string(r.Key.value), true
			}
		}
		return lookup(name)
	}
}

// Bootstrap runs the startup sequence of the container: resolve DATA_DIR,
// let prepare create and restrict the directory (internal/platform), resolve
// the secret, then Load.
func Bootstrap(lookup LookupFunc, prepare func(dataDir string) error) (Config, []Warning, error) {
	dataDir, err := ResolveDataDir(lookup)
	if err != nil {
		return Config{}, nil, err
	}
	if prepare != nil {
		if err := prepare(dataDir); err != nil {
			return Config{}, nil, err
		}
	}
	sec, warns, err := ResolveSecretKey(dataDir, lookup)
	if err != nil {
		return Config{}, warns, err
	}
	c, more, err := Load(sec.Overlay(dataDir, lookup))
	return c, append(warns, more...), err
}
