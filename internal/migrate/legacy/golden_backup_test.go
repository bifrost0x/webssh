package legacy

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	json "encoding/json/v2"
	"errors"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

var goldenBackups = map[string]string{
	"export":            "export.zip",
	"online":            "online.zip",
	"recovery_snapshot": "online-recovery-snapshot.zip",
}

func backupPath(name string) string {
	return filepath.Join(fixtureDir, "artifacts", "backups", goldenBackups[name])
}

// openExtracted verifies an archive, extracts it and opens it as a
// legacy DATA_DIR.
func openExtracted(t *testing.T, archive string) (*Backup, *Source) {
	t.Helper()
	b, err := OpenBackup(archive, DefaultBackupLimits)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.Close() })
	dest := t.TempDir()
	if _, err := ExtractBackup(b, dest, DefaultBackupLimits); err != nil {
		t.Fatal(err)
	}
	src, err := Open(t.Context(), dest, golden.manifest.SecretKey.Value, PrivateCopy())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { src.Close() })
	if err := src.CheckIntegrity(t.Context()); err != nil {
		t.Fatal(err)
	}
	return b, src
}

func TestGoldenBackups(t *testing.T) {
	t.Parallel()
	owner := goldenUserByName(t, "local_user").ID
	for name := range goldenBackups {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			want := golden.manifest.Values.Backups[name]
			b, src := openExtracted(t, backupPath(name))
			m := b.Manifest
			if m.FormatVersion != want.FormatVersion || m.DataSchemaVersion != want.DataSchemaVersion ||
				m.CreatedAt != want.CreatedAt || m.Producer != "webssh" || !slices.Equal(m.Files, want.Files) {
				t.Fatalf("manifest %+v", m)
			}
			users, err := src.Users(t.Context())
			if err != nil || len(users) != len(golden.manifest.Values.Users) {
				t.Fatalf("users %d, %v", len(users), err)
			}
			if _, err := src.UserDocuments(owner); err != nil {
				t.Fatal(err)
			}
			hasSecrets := slices.ContainsFunc(m.Files, func(f BackupFile) bool {
				return strings.Contains(f.Path, "/keys/") || strings.HasSuffix(f.Path, "credentials.json") || strings.HasSuffix(f.Path, "automation-vault.json")
			})
			if hasSecrets != (name == "recovery_snapshot") {
				t.Fatalf("secrets in %s: %v", name, hasSecrets)
			}
			if !hasSecrets {
				return
			}
			keys, err := src.SSHKeys(owner)
			if err != nil || len(keys.Keys) == 0 {
				t.Fatalf("keys %d, %v", len(keys.Keys), err)
			}
			creds, _, err := src.NamedCredentials(t.Context(), owner)
			if err != nil || len(creds) == 0 {
				t.Fatalf("credentials %d, %v", len(creds), err)
			}
		})
	}
}

// rewriteArchive copies an archive, letting edit change the manifest
// document and the member list. Format 1 archives are not part of the
// golden data set (the current release writes format 2); this derives
// one from a real format 2 archive, following app/backup_manager.py.
func rewriteArchive(t *testing.T, src string, edit func(manifest map[string]any, members map[string][]byte)) string {
	t.Helper()
	zr, err := zip.OpenReader(src)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	members := map[string][]byte{}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatal(err)
		}
		members[f.Name] = data
	}
	var manifest map[string]any
	if err := json.Unmarshal(members[backupManifestName], &manifest); err != nil {
		t.Fatal(err)
	}
	edit(manifest, members)
	if members[backupManifestName], err = json.Marshal(manifest, json.Deterministic(true)); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "archive.zip")
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, name := range slices.Sorted(maps.Keys(members)) {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(members[name]); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestBackupFormatOne(t *testing.T) {
	t.Parallel()
	archive := rewriteArchive(t, backupPath("export"), func(m map[string]any, _ map[string][]byte) {
		m["format_version"] = 1
		delete(m, "created_at")
		delete(m, "data_schema_version")
		delete(m, "producer")
	})
	b, src := openExtracted(t, archive)
	if b.Manifest.FormatVersion != 1 || b.Manifest.DataSchemaVersion != 0 || b.Manifest.CreatedAt != "" {
		t.Fatalf("manifest %+v", b.Manifest)
	}
	if users, err := src.Users(t.Context()); err != nil || len(users) != len(golden.manifest.Values.Users) {
		t.Fatalf("users %d, %v", len(users), err)
	}
}

func TestBackupRejections(t *testing.T) {
	t.Parallel()
	addFile := func(m map[string]any, members map[string][]byte, path string, data []byte) {
		sum := sha256.Sum256(data)
		files := append(m["files"].([]any), map[string]any{"path": path, "sha256": hex.EncodeToString(sum[:]), "size": len(data)})
		slices.SortFunc(files, func(a, b any) int {
			return strings.Compare(a.(map[string]any)["path"].(string), b.(map[string]any)["path"].(string))
		})
		m["files"] = files
		members[backupDataPrefix+path] = data
	}
	tests := []struct {
		name string
		edit func(map[string]any, map[string][]byte)
	}{
		{"changed content", func(_ map[string]any, ms map[string][]byte) {
			ms["data/known_hosts"] = append(ms["data/known_hosts"], '\n')
		}},
		{"changed content, same size", func(_ map[string]any, ms map[string][]byte) { ms["data/known_hosts"][0] ^= 0x01 }},
		{"member not in manifest", func(_ map[string]any, ms map[string][]byte) { ms["data/extra"] = []byte("x") }},
		{"manifest entry without member", func(_ map[string]any, ms map[string][]byte) { delete(ms, "data/known_hosts") }},
		{"traversal path", func(m map[string]any, ms map[string][]byte) { addFile(m, ms, "../escape", []byte("x")) }},
		{"colon in path", func(m map[string]any, ms map[string][]byte) { addFile(m, ms, "c:evil", []byte("x")) }},
		{"sqlite sidecar", func(m map[string]any, ms map[string][]byte) { addFile(m, ms, "app.db-wal", []byte("x")) }},
		{"ambiguous database", func(m map[string]any, ms map[string][]byte) { addFile(m, ms, "APP.DB", []byte("x")) }},
		{"unsorted files", func(m map[string]any, _ map[string][]byte) { f := m["files"].([]any); f[0], f[1] = f[1], f[0] }},
		{"foreign producer", func(m map[string]any, _ map[string][]byte) { m["producer"] = "other" }},
		{"newer data schema", func(m map[string]any, _ map[string][]byte) { m["data_schema_version"] = 3 }},
		{"unknown format", func(m map[string]any, _ map[string][]byte) { m["format_version"] = 3 }},
		{"extra manifest member", func(m map[string]any, _ map[string][]byte) { m["note"] = "x" }},
		{"bad timestamp", func(m map[string]any, _ map[string][]byte) { m["created_at"] = "2026-11-02T09:09:56" }},
		{"uppercase digest", func(m map[string]any, _ map[string][]byte) {
			f := m["files"].([]any)[0].(map[string]any)
			f["sha256"] = strings.ToUpper(f["sha256"].(string))
		}},
		{"no manifest", func(map[string]any, map[string][]byte) {}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			archive := rewriteArchive(t, backupPath("export"), tt.edit)
			if tt.name == "no manifest" {
				archive = rewriteNoManifest(t, archive)
			}
			if b, err := OpenBackup(archive, DefaultBackupLimits); !errors.Is(err, ErrBackup) {
				if b != nil {
					b.Close()
				}
				t.Fatalf("err = %v, want ErrBackup", err)
			}
		})
	}
}

// rewriteNoManifest removes manifest.json from an archive.
func rewriteNoManifest(t *testing.T, archive string) string {
	t.Helper()
	zr, err := zip.OpenReader(archive)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, f := range zr.File {
		if f.Name != backupManifestName {
			if err := zw.Copy(f); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "no-manifest.zip")
	if err := os.WriteFile(out, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestBackupLimits(t *testing.T) {
	t.Parallel()
	limits := DefaultBackupLimits
	limits.FileSize = 1000 // app.db is larger
	if _, err := OpenBackup(backupPath("export"), limits); !errors.Is(err, ErrBackup) {
		t.Fatalf("file size limit: %v", err)
	}
	limits = DefaultBackupLimits
	limits.Members = 3
	if _, err := OpenBackup(backupPath("export"), limits); !errors.Is(err, ErrBackup) {
		t.Fatalf("member limit: %v", err)
	}
}

func TestExtractBackupNeedsEmptyDirectory(t *testing.T) {
	t.Parallel()
	b, err := OpenBackup(backupPath("export"), DefaultBackupLimits)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	dest := t.TempDir()
	if err := os.WriteFile(filepath.Join(dest, "present"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ExtractBackup(b, dest, DefaultBackupLimits); err == nil {
		t.Fatal("extracted into a non-empty directory")
	}
}
