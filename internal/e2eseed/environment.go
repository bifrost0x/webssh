package e2eseed

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Placeholders of seed environment values.
const (
	portPlaceholder    = "{port}"
	dataDirPlaceholder = "{data_dir}/"
)

// DefaultPort is the loopback port when WEBSSH_E2E_PORT is unset, as in
// playwright.config.js.
const DefaultPort = 4173

// ParsePort parses WEBSSH_E2E_PORT; an empty value yields DefaultPort.
func ParsePort(value string) (int, error) {
	if value == "" {
		return DefaultPort, nil
	}
	port, err := strconv.Atoi(value)
	if err != nil || port < 1 || port > 65535 || strconv.Itoa(port) != value {
		return 0, fmt.Errorf("WEBSSH_E2E_PORT %q is not a port number", value)
	}
	return port, nil
}

// Scratch is the private, empty directory tree of one run: the data
// directory and the separate scratch directories for backups and
// transfers, as siblings under one temporary root.
type Scratch struct {
	Root, DataDir, BackupDir, TransferDir string
}

// NewScratch creates a fresh tree under parent ("" for the system
// temporary directory). Every directory has mode 0700.
func NewScratch(parent string) (*Scratch, error) {
	root, err := os.MkdirTemp(parent, "webssh-e2e-")
	if err != nil {
		return nil, fmt.Errorf("e2e scratch: %w", err)
	}
	s := &Scratch{
		Root:        root,
		DataDir:     filepath.Join(root, "data"),
		BackupDir:   filepath.Join(root, "backups"),
		TransferDir: filepath.Join(root, "transfers"),
	}
	for _, dir := range []string{s.DataDir, s.BackupDir, s.TransferDir} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			return nil, errors.Join(fmt.Errorf("e2e scratch: %w", err), s.Remove())
		}
	}
	return s, nil
}

// Remove deletes the whole tree of the run.
func (s *Scratch) Remove() error {
	if err := os.RemoveAll(s.Root); err != nil {
		return fmt.Errorf("e2e scratch: %w", err)
	}
	return nil
}

// WriteDataFiles writes the seed's data files into the data directory with
// mode 0600. A file that already exists is an error, so a name can never
// replace something the harness created.
func (s *Scratch) WriteDataFiles(files map[string]string) error {
	root, err := os.OpenRoot(s.DataDir)
	if err != nil {
		return fmt.Errorf("e2e data files: %w", err)
	}
	defer root.Close()
	for name, content := range files {
		if !plainFileName(name) {
			return fmt.Errorf("e2e data files: %q is not a plain file name", name)
		}
		f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return fmt.Errorf("e2e data files: %w", err)
		}
		_, werr := f.WriteString(content)
		if err := errors.Join(werr, f.Close()); err != nil {
			return fmt.Errorf("e2e data files %s: %w", name, err)
		}
	}
	return nil
}

// Config returns the configuration of the backend: the process
// environment without the seed's unset_environment, the storage locations
// of the scratch tree, and the seed's environment with its placeholders
// expanded. Later sources win, as in run_app.py; the seed cannot override
// the storage locations (Validate refuses them).
//
// The result is a lookup for the configuration loader. The process
// environment itself is not changed.
func (s *Seed) Config(base []string, port int, sc *Scratch) map[string]string {
	env := make(map[string]string, len(base)+len(s.Environment)+3)
	for _, kv := range base {
		if name, value, ok := strings.Cut(kv, "="); ok && name != "" {
			env[name] = value
		}
	}
	env["DATA_DIR"] = sc.DataDir
	env["BACKUP_TEMP_DIR"] = sc.BackupDir
	env["TRANSFER_TEMP_DIR"] = sc.TransferDir
	p := strconv.Itoa(port)
	for name, value := range s.Environment {
		if rest, ok := strings.CutPrefix(value, dataDirPlaceholder); ok {
			value = filepath.Join(sc.DataDir, rest)
		}
		env[name] = strings.ReplaceAll(value, portPlaceholder, p)
	}
	for _, name := range s.UnsetEnvironment {
		delete(env, name)
	}
	return env
}
