package legacy

import (
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Backup archives of the Python release (app/backup_manager.py): a ZIP
// with manifest.json and the files of DATA_DIR under data/. Format 1 has
// only files and format_version; format 2 adds created_at,
// data_schema_version and producer.

// ErrBackup reports an archive that is unsafe, malformed or fails
// verification.
var ErrBackup = errors.New("legacy: invalid backup")

// BackupFile is one manifest entry. Path is as written in the manifest;
// the member is "data/" + Path.
type BackupFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   uint64 `json:"size"`
}

// BackupManifest is a parsed and checked manifest.
type BackupManifest struct {
	FormatVersion     int
	DataSchemaVersion int
	CreatedAt         string // format 2 only
	Producer          string // format 2 only
	Files             []BackupFile
}

const (
	backupManifestName  = "manifest.json"
	backupDataPrefix    = "data/"
	backupDatabase      = "app.db"
	currentSchemaFormat = 2
)

var sqliteSidecars = []string{"app.db-wal", "app.db-shm", "app.db-journal"}

func backupError(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrBackup, fmt.Sprintf(format, args...))
}

// normalizeBackupPath applies app/backup_manager.py _safe_relative_path
// with PurePosixPath semantics, tolerant as Python is for Python archives
// (D-30): empty and "." components are dropped, so "a//b" and "./a" are
// accepted as "a/b" and "a". Rejected: empty, absolute, a backslash, a
// ".." component, ":" in a component, or nothing left.
func normalizeBackupPath(p string) (string, bool) {
	if p == "" || strings.ContainsRune(p, '\\') || strings.HasPrefix(p, "/") {
		return "", false
	}
	var parts []string
	for part := range strings.SplitSeq(p, "/") {
		switch {
		case part == "" || part == ".":
		case part == ".." || strings.ContainsRune(part, ':'):
			return "", false
		default:
			parts = append(parts, part)
		}
	}
	if len(parts) == 0 {
		return "", false
	}
	return strings.Join(parts, "/"), true
}

// safeBackupPath reports whether p is acceptable to normalizeBackupPath.
func safeBackupPath(p string) bool {
	_, ok := normalizeBackupPath(p)
	return ok
}

// foldName approximates Python's str.casefold for comparing names with
// the fixed ASCII names above: every rune that case-folds to an ASCII
// letter (including U+017F long s and U+212A Kelvin sign) becomes that
// lowercase letter.
func foldName(s string) string {
	var b strings.Builder
	for _, r := range s {
		folded := unicode.ToLower(r)
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			if f < utf8.RuneSelf {
				folded = unicode.ToLower(f)
			}
		}
		b.WriteRune(folded)
	}
	return b.String()
}

// parseBackupManifest checks a manifest as strictly as the Python release:
// exact member sets, lowercase SHA-256 hex, sorted unique paths, and the
// normalised paths unique as well.
func parseBackupManifest(payload []byte) (BackupManifest, error) {
	var members map[string]jsontext.Value
	if err := json.Unmarshal(payload, &members); err != nil {
		return BackupManifest{}, backupError("manifest is not a JSON object")
	}
	var m BackupManifest
	if err := json.Unmarshal(members["format_version"], &m.FormatVersion); err != nil {
		return BackupManifest{}, backupError("manifest has no format_version")
	}
	want := []string{"files", "format_version"}
	switch m.FormatVersion {
	case 1:
	case 2:
		want = []string{"created_at", "data_schema_version", "files", "format_version", "producer"}
		if json.Unmarshal(members["data_schema_version"], &m.DataSchemaVersion) != nil || m.DataSchemaVersion < 0 ||
			json.Unmarshal(members["producer"], &m.Producer) != nil || m.Producer != "webssh" ||
			json.Unmarshal(members["created_at"], &m.CreatedAt) != nil || !validUTCTimestamp(m.CreatedAt) {
			return BackupManifest{}, backupError("manifest is incompatible")
		}
	default:
		return BackupManifest{}, backupError("unsupported format_version %d", m.FormatVersion)
	}
	if !slices.Equal(slices.Sorted(maps.Keys(members)), want) {
		return BackupManifest{}, backupError("manifest is incompatible")
	}
	if m.DataSchemaVersion > currentSchemaFormat {
		return BackupManifest{}, backupError("backup data schema is newer than this release")
	}
	if err := json.Unmarshal(members["files"], &m.Files, json.RejectUnknownMembers(true)); err != nil || m.Files == nil {
		return BackupManifest{}, backupError("manifest files are invalid")
	}
	normalized := map[string]bool{}
	for i, f := range m.Files {
		norm, ok := normalizeBackupPath(f.Path)
		if !ok || len(f.SHA256) != 64 || strings.Trim(f.SHA256, "0123456789abcdef") != "" {
			return BackupManifest{}, backupError("manifest entry %d is invalid", i)
		}
		if i > 0 && m.Files[i-1].Path >= f.Path {
			return BackupManifest{}, backupError("manifest paths must be unique and sorted")
		}
		if normalized[norm] {
			return BackupManifest{}, backupError("manifest paths %q collide after normalisation", norm)
		}
		normalized[norm] = true
	}
	return m, nil
}

// validUTCTimestamp accepts Python isoformat UTC text ending in "Z"
// (app/backup_manager.py _valid_utc_timestamp).
func validUTCTimestamp(s string) bool {
	body, ok := strings.CutSuffix(s, "Z")
	if !ok {
		return false
	}
	dt, err := pythonFromISOFormat(body + "+00:00")
	return err == nil && dt.hasOffset && dt.offset == 0
}
