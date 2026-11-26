package legacy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"unicode/utf8"
)

// RestoreStatus is BACKUP_TEMP_DIR/instance-<hash>/restore-status.json,
// the state of a restore the Python release runs (migration specification
// A10, app/maintenance_mode.py).
type RestoreStatus struct {
	Path  string
	State string // "" when the file does not exist
	// Unreadable reports a file Python cannot read or validate; Python
	// then treats it as rollback_failed.
	Unreadable bool
}

// Unfinished reports a restore that keeps Python in maintenance:
// preparing, in_progress or rollback_failed (also an unreadable file).
// The migration stops on it (A10).
func (r RestoreStatus) Unfinished() bool {
	return slices.Contains([]string{"preparing", "in_progress", "rollback_failed"}, r.State)
}

var restoreStates = []string{"preparing", "in_progress", "succeeded", "failed", "rollback_failed"}

// BackupNamespace returns Python's per-DATA_DIR operation directory below
// backupTempDir: "instance-" and the first 32 hex digits of the SHA-256
// of the resolved DATA_DIR (app/backup_coordination.py
// ensure_backup_temp_dir). It creates nothing.
func BackupNamespace(backupTempDir, dataDir string) (string, error) {
	root, err := resolveLoose(expandUser(backupTempDir))
	if err != nil {
		return "", err
	}
	data, err := resolveLoose(expandUser(dataDir))
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(data))
	return filepath.Join(root, "instance-"+hex.EncodeToString(sum[:])[:32]), nil
}

// ReadRestoreStatus reads restore-status.json in namespace. A missing
// namespace or file is no restore. A file Python would reject reads as
// rollback_failed, as in Python. A namespace that is a link or not a
// directory is an error: Python refuses to run any backup operation then.
func ReadRestoreStatus(namespace string) (RestoreStatus, error) {
	path := filepath.Join(namespace, "restore-status.json")
	out := RestoreStatus{Path: path}
	for _, dir := range []string{filepath.Dir(namespace), namespace} {
		info, err := os.Lstat(dir)
		if errors.Is(err, fs.ErrNotExist) {
			return out, nil
		}
		if err != nil {
			return out, fmt.Errorf("legacy: inspect %s: %w", dir, err)
		}
		if !info.IsDir() {
			return out, fmt.Errorf("%w: %s", ErrUnsafePath, dir)
		}
	}
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return out, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxFileBytes {
		out.State, out.Unreadable = "rollback_failed", true
		return out, nil
	}
	data, err := os.ReadFile(path) // #nosec G304 -- Python's restore status file below BACKUP_TEMP_DIR
	state, ok := parseRestoreStatus(data)
	if err != nil || !ok {
		out.State, out.Unreadable = "rollback_failed", true
		return out, nil
	}
	out.State = state
	return out, nil
}

// parseRestoreStatus is app/maintenance_mode.py _valid_status_document; it
// returns the state of a valid document.
func parseRestoreStatus(data []byte) (string, bool) {
	var doc map[string]jsontext.Value
	if !utf8.Valid(data) || json.Unmarshal(data, &doc, jsontext.AllowDuplicateNames(true)) != nil || doc == nil {
		return "", false
	}
	state, ok := jsonString(doc["state"])
	if !ok || !slices.Contains(restoreStates, state) {
		return "", false
	}
	op, ok := jsonString(doc["operation_id"])
	if !ok || op == "" || utf8.RuneCountInString(op) > 256 {
		return "", false
	}
	if _, ok := jsonString(doc["message"]); !ok || doc["updated_at"].Kind() != '0' {
		return "", false
	}
	fingerprint, hasFingerprint, ok := optionalString(doc["data_fingerprint"])
	if !ok || hasFingerprint && !isLowerHex(fingerprint, 64) {
		return "", false
	}
	rollback, hasRollback, ok := optionalString(doc["rollback_relative"])
	if !ok || hasRollback && !safeRollbackRelative(rollback) {
		return "", false
	}
	switch {
	case state == "in_progress" && !(hasFingerprint && hasRollback), state == "preparing" && !hasFingerprint:
		return "", false
	}
	return state, true
}

func jsonString(raw jsontext.Value) (string, bool) {
	if raw == nil || raw.Kind() != '"' {
		return "", false
	}
	var s string
	return s, json.Unmarshal(raw, &s, jsontext.AllowInvalidUTF8(true)) == nil
}

// optionalString decodes a member that Python reads with .get(): absent
// and null are no value, a string is a value, anything else is invalid.
func optionalString(raw jsontext.Value) (value string, present, ok bool) {
	if raw == nil || raw.Kind() == 'n' {
		return "", false, true
	}
	value, ok = jsonString(raw)
	return value, ok, ok
}

// safeRollbackRelative is _safe_rollback_relative with PurePath on POSIX:
// relative, without "..", exactly two parts after empty and "." parts are
// dropped.
func safeRollbackRelative(p string) bool {
	if strings.HasPrefix(p, "/") {
		return false
	}
	var parts []string
	for part := range strings.SplitSeq(p, "/") {
		switch part {
		case "", ".":
		case "..":
			return false
		default:
			parts = append(parts, part)
		}
	}
	return len(parts) == 2
}

// expandUser is os.path.expanduser for "~" and "~/...".
func expandUser(p string) string {
	if p != "~" && !strings.HasPrefix(p, "~/") {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return p
	}
	return filepath.Join(home, strings.TrimPrefix(p, "~"))
}

// resolveLoose is Path.resolve(strict=False): an absolute path with every
// existing prefix's links resolved and the missing rest appended.
func resolveLoose(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", fmt.Errorf("legacy: resolve %s: %w", p, err)
	}
	rest := ""
	for cur := abs; ; cur = filepath.Dir(cur) {
		resolved, err := filepath.EvalSymlinks(cur)
		if err == nil {
			return filepath.Join(resolved, rest), nil
		}
		if !errors.Is(err, fs.ErrNotExist) || filepath.Dir(cur) == cur {
			return "", fmt.Errorf("legacy: resolve %s: %w", p, err)
		}
		rest = filepath.Join(filepath.Base(cur), rest)
	}
}
