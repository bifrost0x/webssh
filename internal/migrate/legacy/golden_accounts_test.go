package legacy

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/bifrost0x/webssh/internal/otp"
)

func TestGoldenFilesMatchManifest(t *testing.T) {
	t.Parallel()
	listed := map[string]bool{}
	for _, f := range golden.manifest.Files {
		base := fixtureDir
		if strings.HasPrefix(f.Path, "data/") {
			base = golden.root
			listed[f.Path] = true
		}
		content, err := os.ReadFile(filepath.Join(base, filepath.FromSlash(f.Path)))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(content)
		if int64(len(content)) != f.Size || (f.Deterministic && hex.EncodeToString(sum[:]) != f.SHA256) {
			t.Errorf("%s: size %d sha %x, manifest %d %s", f.Path, len(content), sum, f.Size, f.SHA256)
		}
	}
	present := map[string]bool{}
	err := filepath.WalkDir(golden.dataDir, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			rel, _ := filepath.Rel(golden.root, p)
			present[filepath.ToSlash(rel)] = true
		}
		return err
	})
	if err != nil || len(present) != len(listed) {
		t.Fatalf("data files %d, manifest lists %d (%v)", len(present), len(listed), err)
	}
}

func TestGoldenSecretKey(t *testing.T) {
	t.Parallel()
	got, err := SecretFromFile(golden.dataDir)
	if err != nil || got != golden.manifest.SecretKey.Value || got != golden.manifest.Environment["SECRET_KEY"] {
		t.Fatalf("SecretFromFile = %q, %v", got, err)
	}
}

func TestGoldenDatabase(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	if err := golden.source.CheckIntegrity(ctx); err != nil {
		t.Fatal(err)
	}
	counts, err := golden.source.Tables(ctx)
	if err != nil {
		t.Fatal(err)
	}
	v := golden.manifest.Values
	live := 0
	for _, vec := range v.WebAuthnVectors {
		if vec.CredentialRowID != v.EdgeCases.PasskeyDeleted.ID {
			live++
		}
	}
	want := map[string]int64{
		"users":                int64(len(v.Users)),
		"webauthn_credentials": int64(live),
		"recovery_codes":       int64(len(v.EdgeCases.RecoveryCode.Remaining) + len(v.PasskeyRecoveryCodes)),
		"totp_authenticators":  1,
		"totp_enrollments":     1,
	}
	for table, n := range want {
		if counts[table] != n {
			t.Errorf("%s: %d rows, want %d", table, counts[table], n)
		}
	}
	// Every table the manifest's entity inventory names must be read.
	table := regexp.MustCompile(`^[a-z_]+$`)
	for _, e := range golden.manifest.EntityInventory {
		if strings.ContainsAny(e.Source, "/(") {
			continue // files, downloads and configuration, not tables
		}
		for name := range strings.FieldsFuncSeq(e.Source, func(r rune) bool { return r == ',' || r == '+' || r == ' ' }) {
			if _, ok := counts[name]; table.MatchString(name) && name != "cookies" && !ok {
				t.Errorf("table %s of %q not read", name, e.Entity)
			}
		}
	}
}

func TestGoldenUsers(t *testing.T) {
	t.Parallel()
	users, err := golden.source.Users(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != len(golden.manifest.Values.Users) {
		t.Fatalf("%d users, manifest has %d", len(users), len(golden.manifest.Values.Users))
	}
	for _, u := range users {
		t.Run(u.Username, func(t *testing.T) {
			t.Parallel()
			want := goldenUserByName(t, u.Username)
			if u.ID != want.ID || u.IsAdmin != want.IsAdmin || u.IsLocked != want.IsLocked ||
				u.MFAEnabled != want.MFAEnabled || u.AuthGeneration != want.AuthGeneration {
				t.Fatalf("row %+v, manifest %+v", u, want)
			}
			incarnation, err := u.Incarnation()
			if err != nil || incarnation != want.CreatedAtDB {
				t.Fatalf("incarnation %q, %v, want %q", incarnation, err, want.CreatedAtDB)
			}
			scope, err := golden.source.ConnectionHistoryScope(u)
			if err != nil || scope != want.ConnectionHistoryScope {
				t.Fatalf("connection history scope %q, %v", scope, err)
			}
			if cost, err := BcryptCost(u.PasswordHash); err != nil || cost != 12 {
				t.Fatalf("bcrypt cost %d, %v", cost, err)
			}
			if want.Password == nil {
				return // directory- and GitHub-managed: random unknown password
			}
			if err := VerifyPassword(u.PasswordHash, *want.Password); err != nil {
				t.Fatalf("VerifyPassword: %v", err)
			}
			if err := VerifyPassword(u.PasswordHash, *want.Password+"x"); !errors.Is(err, ErrPasswordMismatch) {
				t.Fatalf("wrong password: %v", err)
			}
		})
	}
}

func TestGoldenPasswordAtBcryptLimit(t *testing.T) {
	t.Parallel()
	want := goldenUserByName(t, "limit_user")
	if len(*want.Password) != 72 {
		t.Fatalf("manifest password has %d bytes", len(*want.Password))
	}
	users, _ := golden.source.Users(t.Context())
	i := slices.IndexFunc(users, func(u User) bool { return u.ID == want.ID })
	if err := VerifyPassword(users[i].PasswordHash, *want.Password); err != nil {
		t.Fatal(err)
	}
	// One byte more than bcrypt reads: Python refuses it before hashing.
	if err := VerifyPassword(users[i].PasswordHash, *want.Password+"x"); !errors.Is(err, ErrPasswordMismatch) {
		t.Fatalf("73 bytes: %v", err)
	}
}

func TestGoldenTOTP(t *testing.T) {
	t.Parallel()
	facts := golden.manifest.Values.TOTP
	secrets, err := golden.source.TOTPSecrets(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	totpUser := goldenUserByName(t, "totp_user")
	var active, pending int
	for _, s := range secrets {
		switch {
		case s.Pending:
			pending++
			if s.Base32 != golden.manifest.Values.TOTPPending.SecretBase32 {
				t.Errorf("pending secret %q", s.Base32)
			}
		case s.Active:
			active++
			if s.ID != facts.AuthenticatorID || s.UserID != totpUser.ID || s.Base32 != facts.SecretBase32 {
				t.Errorf("authenticator %d of user %d: %q", s.ID, s.UserID, s.Base32)
			}
			if !s.LastStep.Valid || uint64(s.LastStep.Int64) != facts.ActivationStep {
				t.Errorf("last accepted step %v, want %d", s.LastStep, facts.ActivationStep)
			}
			code, err := otp.TOTP(s.Key, facts.ActivationStep)
			if err != nil || code != facts.ActivationCode {
				t.Errorf("TOTP at activation step = %q, %v, want %q", code, err, facts.ActivationCode)
			}
		}
	}
	if active != 1 || pending != 1 {
		t.Fatalf("active %d pending %d", active, pending)
	}
}

func TestGoldenRecoveryCodes(t *testing.T) {
	t.Parallel()
	hashes, err := golden.source.RecoveryCodeHashes(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	edge := golden.manifest.Values.EdgeCases.RecoveryCode
	tests := []struct {
		name      string
		user      string
		remaining []string
		consumed  string
	}{
		{"totp user", "totp_user", edge.Remaining, edge.Consumed},
		{"passkey user", "passkey_user", golden.manifest.Values.PasskeyRecoveryCodes, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			stored := hashes[goldenUserByName(t, tt.user).ID]
			if len(stored) != len(tt.remaining) {
				t.Fatalf("%d stored, %d expected", len(stored), len(tt.remaining))
			}
			for _, code := range tt.remaining {
				if !MatchRecoveryCode(stored, code) || !MatchRecoveryCode(stored, " "+strings.ToLower(code)+"\n") {
					t.Errorf("code %s does not match", code)
				}
			}
			if tt.consumed != "" && MatchRecoveryCode(stored, tt.consumed) {
				t.Error("consumed code still matches")
			}
		})
	}
}

func TestGoldenGitHubSecret(t *testing.T) {
	t.Parallel()
	c, err := golden.source.GitHubConfiguration(t.Context())
	if err != nil || c == nil || c.ClientSecret != golden.manifest.Values.GitHubClientSecret {
		t.Fatalf("GitHubConfiguration = %+v, %v", c, err)
	}
}

func TestGoldenExternalIdentities(t *testing.T) {
	t.Parallel()
	ids, err := golden.source.ExternalIdentities(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	byUser := map[int64]string{}
	for _, id := range ids {
		byUser[id.UserID] = id.Provider
	}
	for _, c := range []struct{ user, provider string }{
		{"oidc_user", "oidc"}, {"ldap_user", "ldap"}, {"github_linked", "github"}, {"octo_golden", "github"},
	} {
		if byUser[goldenUserByName(t, c.user).ID] != c.provider {
			t.Errorf("%s: provider %q", c.user, byUser[goldenUserByName(t, c.user).ID])
		}
	}
	features, err := golden.source.SecurityFeatures(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	env := golden.manifest.Environment
	for feature, variable := range map[string]string{"passkey": "WEBAUTHN_ENABLED", "totp": "TOTP_ENABLED", "recovery": "RECOVERY_CODES_ENABLED"} {
		if enabled, ok := features[feature]; !ok || enabled != (env[variable] == "true") {
			t.Errorf("feature %s = %v (present %v), %s=%q", feature, enabled, ok, variable, env[variable])
		}
	}
}
