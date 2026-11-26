package legacy

import (
	"archive/tar"
	"context"
	"encoding/base64"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
)

// The golden data set (tests/golden) is a DATA_DIR produced by the
// unmodified Python application. Every expected value in these tests comes
// from its manifest.json.
const fixtureDir = "../../../tests/golden/fixture"

type goldenManifest struct {
	Files []struct {
		Path          string `json:"path"`
		SHA256        string `json:"sha256"`
		Size          int64  `json:"size"`
		Deterministic bool   `json:"deterministic"`
	} `json:"files"`
	SecretKey struct {
		Value string `json:"value"`
	} `json:"secret_key"`
	Environment     map[string]string `json:"environment"`
	EntityInventory []struct {
		Entity    string `json:"entity"`
		Source    string `json:"source"`
		InFixture bool   `json:"in_fixture"`
	} `json:"entity_inventory"`
	Values goldenValues `json:"values"`
}

type goldenUser struct {
	ID                     int64   `json:"id"`
	IsAdmin                bool    `json:"is_admin"`
	IsLocked               bool    `json:"is_locked"`
	MFAEnabled             bool    `json:"mfa_enabled"`
	AuthGeneration         int64   `json:"auth_generation"`
	CreatedAtDB            string  `json:"created_at_db"`
	Password               *string `json:"password"`
	ConnectionHistoryScope string  `json:"connection_history_scope"`
}

type goldenKey struct {
	Label               string `json:"label"`
	KeyID               string `json:"key_id"`
	KeyType             string `json:"key_type"`
	PlaintextB64        string `json:"plaintext_b64"`
	PublicKeyOpenSSH    string `json:"public_key_openssh"`
	StoredFile          string `json:"stored_file"`
	PassphraseProtected bool   `json:"passphrase_protected"`
	Format              string `json:"format"`
	ExpectedError       string `json:"expected_error"`
}

type goldenValues struct {
	Users   map[string]goldenUser `json:"users"`
	SSHKeys struct {
		Stored          []goldenKey `json:"stored"`
		Rejected        []goldenKey `json:"rejected"`
		LegacyPlaintext goldenKey   `json:"legacy_plaintext"`
	} `json:"ssh_keys"`
	TOTP struct {
		ActivationCode  string   `json:"activation_code"`
		ActivationStep  uint64   `json:"activation_step"`
		AuthenticatorID int64    `json:"authenticator_id"`
		SecretBase32    string   `json:"secret_base32"`
		RecoveryCodes   []string `json:"recovery_codes"`
	} `json:"totp"`
	TOTPPending struct {
		SecretBase32 string `json:"secret_base32"`
	} `json:"totp_pending"`
	PasskeyRecoveryCodes []string `json:"passkey_recovery_codes"`
	GitHubClientSecret   string   `json:"github_client_secret"`
	VaultPassphrase      string   `json:"vault_passphrase"`
	HostKeys             struct {
		GlobalLines []string `json:"global_lines"`
		UserEntries []struct {
			Fingerprint string `json:"fingerprint_sha256"`
			Host        string `json:"host"`
			KeyType     string `json:"key_type"`
		} `json:"user_entries"`
	} `json:"host_keys"`
	NamedCredential goldenCredential `json:"named_credential"`
	Vault           map[string]struct {
		Password  string `json:"password"`
		ProfileID string `json:"profile_id"`
	} `json:"vault"`
	WebAuthnVectors []webauthnVector `json:"webauthn_vectors"`
	Backups         map[string]struct {
		FormatVersion     int          `json:"format_version"`
		DataSchemaVersion int          `json:"data_schema_version"`
		CreatedAt         string       `json:"created_at"`
		Files             []BackupFile `json:"files"`
	} `json:"backups"`
	Connections  map[string]any `json:"connections"`
	Commands     map[string]any `json:"commands"`
	Automation   map[string]any `json:"automation"`
	UserSettings map[string]any `json:"user_settings"`
	HostIdentity map[string]any `json:"host_identity"`
	EdgeCases    goldenEdges    `json:"edge_cases"`
}

type goldenCredential struct {
	Password   string `json:"password"`
	RecordID   string `json:"record_id"`
	ResourceID string `json:"resource_id"`
}

type goldenEdges struct {
	RecoveryCode struct {
		Consumed  string   `json:"consumed"`
		Remaining []string `json:"remaining"`
	} `json:"recovery_code"`
	NamedCredentials struct {
		Deleted           string           `json:"deleted"`
		UnassignedUnicode goldenCredential `json:"unassigned_unicode"`
	} `json:"named_credentials"`
	VaultLongPassword struct {
		Password  string `json:"password"`
		ProfileID string `json:"profile_id"`
	} `json:"vault_long_password"`
	PasskeyDeleted struct {
		ID int64 `json:"id"`
	} `json:"passkey_deleted"`
	HostKeyDeleted struct {
		DeletedHost string `json:"deleted_host"`
	} `json:"host_key_deleted"`
	Keys struct {
		Deleted         string `json:"deleted"`
		Unicode128Chars string `json:"unicode_128_chars"`
	} `json:"keys"`
	Profiles struct {
		Deleted        string `json:"deleted"`
		LongName       string `json:"long_name"`
		StoredLongName string `json:"stored_long_name"`
		Minimal        string `json:"minimal"`
		Unicode        string `json:"unicode"`
	} `json:"profiles"`
	DeletedAccount struct {
		FormerID      int64  `json:"former_id"`
		QuarantineDir string `json:"quarantine_dir"`
	} `json:"deleted_account"`
	AdminSettings map[string][]any  `json:"admin_settings"`
	Commands      map[string]string `json:"commands"`
	Routes        map[string]string `json:"routes"`
	HostContext   map[string]any    `json:"host_context"`
	Automation    map[string]any    `json:"automation"`
}

var golden struct {
	manifest goldenManifest
	root     string // parent of data/
	dataDir  string
	source   *Source
}

func TestMain(m *testing.M) {
	code, err := runWithFixture(m)
	if err != nil {
		fmt.Fprintln(os.Stderr, "golden fixture:", err)
		os.Exit(1)
	}
	os.Exit(code)
}

func runWithFixture(m *testing.M) (int, error) {
	raw, err := os.ReadFile(filepath.Join(fixtureDir, "manifest.json"))
	if err != nil {
		return 0, err
	}
	if err := json.Unmarshal(raw, &golden.manifest); err != nil {
		return 0, err
	}
	golden.root, err = os.MkdirTemp("", "legacy-golden-")
	if err != nil {
		return 0, err
	}
	defer os.RemoveAll(golden.root)
	if err := extractTar(filepath.Join(fixtureDir, "datadir.tar"), golden.root); err != nil {
		return 0, err
	}
	golden.dataDir = filepath.Join(golden.root, "data")
	golden.source, err = Open(context.Background(), golden.dataDir, golden.manifest.SecretKey.Value)
	if err != nil {
		return 0, err
	}
	code := m.Run()
	return code, golden.source.Close()
}

// extractTar unpacks the fixture: regular files and directories only,
// below dest, as tests/golden/packing.py extract_data_dir does.
func extractTar(archive, dest string) error {
	f, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer f.Close()
	root, err := os.OpenRoot(dest)
	if err != nil {
		return err
	}
	defer root.Close()
	tr := tar.NewReader(f)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		name := strings.TrimSuffix(h.Name, "/")
		if !safeBackupPath(name) || path.Clean(name) != name {
			return fmt.Errorf("unsafe tar member %q", h.Name)
		}
		switch h.Typeflag {
		case tar.TypeDir:
			if err := root.MkdirAll(name, 0o700); err != nil {
				return err
			}
		case tar.TypeReg:
			out, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, os.FileMode(h.Mode)&0o600)
			if err != nil {
				return err
			}
			_, copyErr := io.Copy(out, io.LimitReader(tr, h.Size))
			if err := errors.Join(copyErr, out.Close()); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unsupported tar member %q", h.Name)
		}
	}
}

func goldenUserByName(t *testing.T, name string) goldenUser {
	t.Helper()
	u, ok := golden.manifest.Values.Users[name]
	if !ok {
		t.Fatalf("manifest has no user %q", name)
	}
	return u
}

func mustB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
