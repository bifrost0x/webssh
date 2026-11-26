package legacy

import (
	"bytes"
	"encoding/base64"
	json "encoding/json/v2"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
)

// Golden legacy data set (tests/golden/fixture/legacy): DATA_DIRs written by
// old releases (2fcd38a, v1.0.0), a 3.3.x DATA_DIR with every boundary
// case of specification 8.2, and Python backups. Expected values come
// from legacy/manifest.json.
const legacyFixtureDir = fixtureDir + "/legacy"

type legacyKey struct {
	Filename     string `json:"filename"`
	KeyID        string `json:"key_id"`
	KeyType      string `json:"key_type"`
	PlaintextB64 string `json:"plaintext_b64"`
}

type legacyUser struct {
	ID       int64  `json:"id"`
	Password string `json:"password"`
}

type legacyManifest struct {
	SecretKey struct {
		Value string `json:"value"`
	} `json:"secret_key"`
	Datadirs map[string]struct {
		Values struct {
			Command  string                `json:"command"`
			Keys     map[string]legacyKey  `json:"keys"`
			Notepad  string                `json:"notepad"`
			Profiles map[string]string     `json:"profiles"`
			Users    map[string]legacyUser `json:"users"`
			Bulk     struct {
				CommandSet string `json:"command_set"`
				Commands   int    `json:"commands"`
				SetSteps   int    `json:"set_steps"`
			} `json:"bulk"`
			CommandSet string `json:"command_set"`
			JumpHost   string `json:"jump_host"`
		} `json:"values"`
	} `json:"datadirs"`
	Backups map[string]struct {
		Values  map[string]any `json:"values"`
		LogPath string         `json:"log_member"`
	} `json:"backups"`
	Values struct {
		Extended extendedValues `json:"extended"`
	} `json:"values"`
	Variants map[string]struct {
		SQL []string `json:"sql"`
	} `json:"variants"`
}

type extendedValues struct {
	AccountSettings map[string]any `json:"account_settings"`
	CreatedAt       map[string]struct {
		Text        *string `json:"created_at_text"`
		Incarnation *string `json:"incarnation"`
		Password    string  `json:"password"`
		UserID      int64   `json:"user_id"`
	} `json:"created_at"`
	DatabaseObjects struct {
		Objects []string `json:"objects"`
	} `json:"database_objects"`
	InterruptedKeyDeletions map[string]struct {
		KeyID        string `json:"key_id"`
		PendingFile  string `json:"pending_file"`
		RestoredFile string `json:"restored_file"`
	} `json:"interrupted_key_deletions"`
	LegacySingleUserPaths []string `json:"legacy_single_user_paths"`
	LegacyStores          struct {
		CommandID string           `json:"command_id"`
		KeyID     string           `json:"key_id"`
		Password  string           `json:"password"`
		Profiles  []map[string]any `json:"profiles"`
		UserID    int64            `json:"user_id"`
	} `json:"legacy_stores"`
	OrphanHostContext struct {
		Notes     string `json:"notes"`
		ProfileID string `json:"profile_id"`
	} `json:"orphan_host_context"`
	ProfilesSchema2 struct {
		Profiles []map[string]any `json:"profiles"`
		UserID   int64            `json:"user_id"`
	} `json:"profiles_schema_2"`
	Schedules map[string]struct {
		ID string `json:"id"`
	} `json:"schedules"`
	TrustAndFences struct {
		CertAuthorityLine string `json:"cert_authority_line"`
	} `json:"trust_and_fences"`
	VaultV1 struct {
		Passphrase string `json:"passphrase"`
		Password   string `json:"password"`
		ProfileID  string `json:"profile_id"`
		UserID     int64  `json:"user_id"`
	} `json:"vault_v1"`
}

var loadLegacyManifest = sync.OnceValues(func() (legacyManifest, error) {
	var m legacyManifest
	raw, err := os.ReadFile(filepath.Join(legacyFixtureDir, "manifest.json"))
	if err != nil {
		return m, err
	}
	return m, json.Unmarshal(raw, &m)
})

func legacyFixture(t *testing.T) legacyManifest {
	t.Helper()
	m, err := loadLegacyManifest()
	if err != nil {
		t.Fatalf("legacy manifest: %v", err)
	}
	return m
}

// extractLegacy unpacks a legacy DATA_DIR into a private directory and
// returns the data directory.
func extractLegacy(t *testing.T, archive string) string {
	t.Helper()
	dest := t.TempDir()
	if err := extractTar(filepath.Join(legacyFixtureDir, archive), dest); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dest, "data")
}

func openLegacy(t *testing.T, dir string) *Source {
	t.Helper()
	src, err := Open(t.Context(), dir, legacyFixture(t).SecretKey.Value)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { src.Close() })
	if err := src.CheckIntegrity(t.Context()); err != nil {
		t.Fatal(err)
	}
	return src
}

func TestLegacyReleaseDataDirs(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"datadir-2fcd38a.tar", "datadir-v1.0.0.tar"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			want := legacyFixture(t).Datadirs[name].Values
			src := openLegacy(t, extractLegacy(t, name))
			if len(src.Schema().MissingUserColumns()) == 0 {
				t.Error("old database reported without missing columns")
			}
			users, err := src.Users(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			byID := map[int64]User{}
			for _, u := range users {
				byID[u.ID] = u
			}
			for uname, u := range want.Users {
				got := byID[u.ID]
				if got.Username != uname || VerifyPassword(got.PasswordHash, u.Password) != nil {
					t.Errorf("user %s: %+v", uname, got)
				}
				if got.IsAdmin != (u.ID == users[0].ID) || got.IsLocked || got.AuthGeneration != 0 || got.MFAEnabled {
					t.Errorf("user %s: defaults %+v", uname, got)
				}
			}
			for _, read := range []func() error{
				func() error { _, err := src.TOTPSecrets(t.Context()); return err },
				func() error { _, err := src.Passkeys(t.Context()); return err },
				func() error { _, err := src.ExternalIdentities(t.Context()); return err },
				func() error { _, err := src.Schedules(t.Context()); return err },
				func() error { _, err := src.GitHubConfiguration(t.Context()); return err },
				func() error { _, err := src.RecoveryCodeHashes(t.Context()); return err },
				func() error { _, err := src.Tables(t.Context()); return err },
			} {
				if err := read(); err != nil {
					t.Errorf("reading a table of an old release: %v", err)
				}
			}
			checkPioneerKeys(t, src, legacyFixture(t).Datadirs["datadir-2fcd38a.tar"].Values.Keys)
			checkPioneerStores(t, src, name)
		})
	}
}

// checkPioneerKeys: the keys of pioneer_user (id 2) as 2fcd38a stored
// them. DSA and passphrase-protected keys are unsupported but kept; the
// PKCS#8 key, unusable in Python, is usable in Go (specification 4.8).
func checkPioneerKeys(t *testing.T, src *Source, want map[string]legacyKey) {
	t.Helper()
	store, err := src.SSHKeys(2)
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]SSHKey{}
	for _, k := range store.Keys {
		byID[k.ID] = k
	}
	states := map[string]KeyState{"dsa_pem": KeyUnsupported, "rsa_pem_passphrase": KeyUnsupported, "rsa_openssh": KeyUsable, "ed25519_pkcs8": KeyUsable}
	for label, k := range want {
		got, ok := byID[k.KeyID]
		plain, _ := base64.StdEncoding.DecodeString(k.PlaintextB64)
		if !ok || got.State != states[label] || !bytes.Equal(got.PEM, plain) || got.Filename != k.Filename {
			t.Errorf("key %s: state %q (%s), present %v", label, got.State, got.Reason, ok)
		}
	}
}

func checkPioneerStores(t *testing.T, src *Source, name string) {
	t.Helper()
	want := legacyFixture(t).Datadirs[name].Values
	docs, err := src.UserDocuments(2)
	if err != nil {
		t.Fatal(err)
	}
	profiles := docs["profiles"]
	if profiles.Version != 0 || !profiles.Lifted {
		t.Errorf("profiles version %d lifted %v", profiles.Version, profiles.Lifted)
	}
	for _, p := range profiles.Items {
		if _, ok := p.(map[string]any)["startup_mode"]; !ok {
			t.Errorf("profile without startup_mode after lifting: %v", p)
		}
	}
	if id := want.Profiles["long_name"]; id != "" {
		if p := findItem(profiles.Items, "id", id); p == nil || len([]rune(p["name"].(string))) <= 128 {
			t.Errorf("long-name profile kept at full length: %v", p)
		}
	}
	for mode, id := range map[string]string{"command_set": want.Profiles["command_set"], "free_text": want.Profiles["free_text"]} {
		if id != "" {
			if p := findItem(profiles.Items, "id", id); p == nil || p["startup_mode"] != mode {
				t.Errorf("profile %s: %v", mode, p)
			}
		}
	}
	if want.Notepad != "" && docs["settings"].Object["notepad"] != want.Notepad {
		t.Errorf("notepad %q", docs["settings"].Object["notepad"])
	}
	if want.Command != "" && findItem(docs["commands"].Items, "id", want.Command) == nil {
		t.Error("command missing")
	}
	if want.Bulk.Commands > 0 {
		bulk, err := src.UserDocuments(4)
		if err != nil {
			t.Fatal(err)
		}
		set := findItem(bulk["command_sets"].Items, "id", want.Bulk.CommandSet)
		if len(bulk["commands"].Items) != want.Bulk.Commands || set == nil || len(set["steps"].([]any)) != want.Bulk.SetSteps {
			t.Errorf("bulk user: %d commands", len(bulk["commands"].Items))
		}
	}
}

func TestLegacyExtendedDataDir(t *testing.T) {
	t.Parallel()
	ext := legacyFixture(t).Values.Extended
	src := openLegacy(t, extractLegacy(t, "datadir-extended.tar"))
	sc := src.Schema()
	for _, obj := range ext.DatabaseObjects.Objects {
		if !sc.HasTable(obj) && !slices.Contains(sc.Indexes, obj) {
			t.Errorf("schema object %s not reported", obj)
		}
	}
	users, err := src.Users(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range ext.CreatedAt {
		i := slices.IndexFunc(users, func(u User) bool { return u.ID == c.UserID })
		if i < 0 || VerifyPassword(users[i].PasswordHash, c.Password) != nil {
			t.Fatalf("%s: user %d", name, c.UserID)
		}
		inc, err := users[i].Incarnation()
		switch {
		case c.Incarnation == nil && !errors.Is(err, ErrNoIncarnation):
			t.Errorf("%s: incarnation %q, %v", name, inc, err)
		case c.Incarnation != nil && (err != nil || inc != *c.Incarnation):
			t.Errorf("%s: incarnation %q, %v, want %q", name, inc, err, *c.Incarnation)
		}
		if _, err := src.ConnectionHistoryScope(users[i]); err != nil {
			t.Errorf("%s: history scope: %v", name, err)
		}
	}
	checkInterruptedDeletions(t, src, ext)
	checkLegacyStores(t, src, ext)
	keys, err := src.GlobalHostKeys()
	if err != nil || !slices.ContainsFunc(keys, func(k HostKey) bool { return k.Marker == "cert-authority" }) {
		t.Errorf("cert-authority line: %v", err)
	}
	paths, err := src.SingleUserPaths()
	if err != nil {
		t.Fatal(err)
	}
	var files int
	for _, p := range paths {
		files += p.Files
	}
	if len(paths) != 3 || files != len(ext.LegacySingleUserPaths) {
		t.Errorf("single-user paths %+v", paths)
	}
	schedules, err := src.Schedules(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for name, s := range ext.Schedules {
		if !slices.ContainsFunc(schedules, func(x Schedule) bool { return x.ID == s.ID }) {
			t.Errorf("schedule %s missing", name)
		}
	}
}

func checkInterruptedDeletions(t *testing.T, src *Source, ext extendedValues) {
	t.Helper()
	store, err := src.SSHKeys(3)
	if err != nil {
		t.Fatal(err)
	}
	for name, d := range ext.InterruptedKeyDeletions {
		pending := filepath.Base(d.PendingFile)
		i := slices.IndexFunc(store.Pending, func(p PendingDeletion) bool { return p.Name == pending })
		k := slices.IndexFunc(store.Keys, func(k SSHKey) bool { return k.ID == d.KeyID })
		restored := d.RestoredFile != ""
		if i < 0 || store.Pending[i].Restored != restored || (k >= 0) != restored {
			t.Errorf("%s: pending %v, key present %v", name, store.Pending, k >= 0)
			continue
		}
		if restored && (store.Keys[k].RecoveredFrom != pending || store.Keys[k].State != KeyUsable) {
			t.Errorf("%s: restored key %+v", name, store.Keys[k].State)
		}
	}
}

func checkLegacyStores(t *testing.T, src *Source, ext extendedValues) {
	t.Helper()
	ls := ext.LegacyStores
	docs, err := src.UserDocuments(ls.UserID)
	if err != nil {
		t.Fatal(err)
	}
	if c := docs["commands"]; !c.Lifted || findItem(c.Items, "id", ls.CommandID) == nil {
		t.Errorf("commands object form: lifted %v", c.Lifted)
	}
	for _, want := range ls.Profiles {
		assertSubset(t, "schema-1 profile", findItem(docs["profiles"].Items, "id", want["id"]), want)
	}
	v2, err := src.UserDocuments(ext.ProfilesSchema2.UserID)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range ext.ProfilesSchema2.Profiles {
		got := findItem(v2["profiles"].Items, "id", want["id"])
		assertSubset(t, "schema-2 profile", got, want)
		if _, has := got["tailscale_authorized"]; has {
			t.Error("tailscale_authorized kept")
		}
	}
	vault, err := src.Vault(ext.VaultV1.UserID)
	if err != nil || vault == nil || vault.Version != 1 {
		t.Fatalf("vault v1: %+v, %v", vault, err)
	}
	records, err := src.VaultRecords(t.Context(), ext.VaultV1.UserID, vault, ext.VaultV1.Passphrase)
	if err != nil || records[ext.VaultV1.ProfileID].Password != ext.VaultV1.Password {
		t.Fatalf("vault v1 records: %v", err)
	}
	owner, err := src.UserDocuments(3)
	if err != nil {
		t.Fatal(err)
	}
	assertSubset(t, "account settings", owner["settings"].Object, ext.AccountSettings)
	host, ok := owner["host_context"].Entries[ext.OrphanHostContext.ProfileID].(map[string]any)
	if !ok || host["notes"] != ext.OrphanHostContext.Notes {
		t.Error("host context of a deleted profile not read")
	}
	store, err := src.SSHKeys(ls.UserID)
	if err != nil || !slices.ContainsFunc(store.Keys, func(k SSHKey) bool { return k.ID == ls.KeyID && k.State == KeyUsable }) {
		t.Errorf("legacy-store key: %v", err)
	}
}

func TestLegacyBackups(t *testing.T) {
	t.Parallel()
	m := legacyFixture(t)
	for name, b := range m.Backups {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			backup, err := OpenBackup(filepath.Join(legacyFixtureDir, name), DefaultBackupLimits)
			if err != nil {
				t.Fatal(err)
			}
			defer backup.Close()
			if want, ok := b.Values["format_version"].(float64); ok && backup.Manifest.FormatVersion != int(want) {
				t.Fatalf("format %d, want %v", backup.Manifest.FormatVersion, want)
			}
			var goFiles, logFiles int
			for _, f := range backup.Manifest.Files {
				goFiles += boolInt(strings.HasPrefix(f.Path, "go/"))
				logFiles += boolInt(strings.HasPrefix(f.Path, "logs/"))
			}
			dest := t.TempDir()
			res, err := ExtractBackup(backup, dest, DefaultBackupLimits)
			if err != nil || res.GoMembers != goFiles || res.LogMembers != logFiles {
				t.Fatalf("extract %+v, %v (go %d, logs %d)", res, err, goFiles, logFiles)
			}
			for _, dir := range []string{"go", "logs"} {
				if _, err := os.Lstat(filepath.Join(dest, dir)); !os.IsNotExist(err) {
					t.Errorf("%s/ was extracted", dir)
				}
			}
			src, err := Open(t.Context(), dest, m.SecretKey.Value, PrivateCopy())
			if err != nil {
				t.Fatal(err)
			}
			defer src.Close()
			if err := src.CheckBackupDatabase(t.Context()); err != nil {
				t.Fatal(err)
			}
			if users, err := src.Users(t.Context()); err != nil || len(users) == 0 {
				t.Fatalf("users %d, %v", len(users), err)
			}
			if p, ok := b.Values["profile"].(string); ok && !backupHasProfile(t, src, p) {
				t.Fatalf("profile %s not found in the restored stores", p)
			}
			if files, ok := b.Values["files"].([]any); ok && len(files) != len(backup.Manifest.Files) {
				t.Fatalf("%d files, manifest lists %d", len(backup.Manifest.Files), len(files))
			}
		})
	}
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func backupHasProfile(t *testing.T, src *Source, id string) bool {
	t.Helper()
	users, err := src.Users(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range users {
		docs, err := src.UserDocuments(u.ID)
		if err != nil {
			t.Fatal(err)
		}
		if findItem(docs["profiles"].Items, "id", id) != nil {
			return true
		}
	}
	return false
}
