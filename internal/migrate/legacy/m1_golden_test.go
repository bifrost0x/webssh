package legacy

import (
	"context"
	"encoding/base64"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/bifrost0x/webssh/internal/accounts"
	"github.com/bifrost0x/webssh/internal/auth"
	"github.com/bifrost0x/webssh/internal/auth/local"
	"github.com/bifrost0x/webssh/internal/auth/totp"
	"github.com/bifrost0x/webssh/internal/hosts"
	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/otp"
	"github.com/bifrost0x/webssh/internal/principal/principaltest"
	"github.com/bifrost0x/webssh/internal/ssh/hostkey"
	"github.com/bifrost0x/webssh/internal/store"
	"github.com/bifrost0x/webssh/internal/vault"
)

func m1Registry(t *testing.T, m M1) *Registry {
	t.Helper()
	r := NewRegistry()
	if err := RegisterM1(r, m); err != nil {
		t.Fatal(err)
	}
	return r
}

func m1Options(t *testing.T, dataDir string, m M1) Options {
	t.Helper()
	o := testOptions(t, dataDir)
	o.Registry = m1Registry(t, m)
	return o
}

// migrated is an activated Go database with its keyring, opened the way
// the composition root opens it after the migration.
type migrated struct {
	db     *store.DB
	ring   *keyring.Ring
	report *Report
}

func migrateM1(t *testing.T, dataDir, secret string, m M1) migrated {
	t.Helper()
	before := legacySnapshot(t, dataDir)
	o := m1Options(t, dataDir, m)
	o.Secret = secret
	st, err := startClosed(o)
	if err != nil || !st.Migrated {
		t.Fatalf("migration: %+v, %v", st, err)
	}
	assertUntouched(t, dataDir, before)
	assertRegularOnly(t, dataDir)
	return openMigrated(t, dataDir, secret, st.Report)
}

func openMigrated(t *testing.T, dataDir, secret string, rep *Report) migrated {
	t.Helper()
	db, err := store.Open(t.Context(), filepath.Join(dataDir, keyring.GoDirName, keyring.DatabaseName), store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	material, err := keyring.LoadOrCreateMaterial(dataDir, true)
	if err != nil {
		t.Fatal(err)
	}
	ring, err := keyring.Open([]byte(secret), material)
	if err != nil {
		t.Fatal(err)
	}
	return migrated{db: db, ring: ring, report: rep}
}

func (m migrated) entity(t *testing.T, id string) StepReport {
	t.Helper()
	for _, e := range m.report.Entities {
		if e.Entity == id {
			return e
		}
	}
	t.Fatalf("no report entry for %s", id)
	return StepReport{}
}

// The whole M1 registry migrates the golden data set; every entity is a
// step or pending, the legacy data stays unchanged (I-01), and a second
// start changes nothing.
func TestM1MigratesGolden(t *testing.T) {
	t.Parallel()
	dir := copyGolden(t)
	m := migrateM1(t, dir, golden.manifest.SecretKey.Value, M1{AdminUsers: []string{"cfg_admin"}})
	covered := map[string]bool{}
	for _, e := range m.report.Entities {
		covered[e.Entity] = true
	}
	for _, p := range m.report.Pending {
		covered[p.Entity] = true
	}
	if len(covered) != len(Entities) {
		t.Fatalf("report covers %d of %d entities", len(covered), len(Entities))
	}
	pending := map[string]Pending{}
	for _, p := range m.report.Pending {
		pending[p.Entity] = p
	}
	for entity, count := range map[string]int{"E15": 2, "E22": 2, "E26": 2, "E27": 3, "E29": 2, "E30": 1, "E31": 1, "E32": 2, "E04": 2} {
		if pending[entity].Count != count || pending[entity].Phase == "" {
			t.Errorf("pending %s: %+v, want count %d", entity, pending[entity], count)
		}
	}
	settingsSeen := map[string]bool{}
	for _, s := range m.report.MaterialisedSettings {
		settingsSeen[s.Setting] = true
	}
	for _, want := range []string{"permission.hosts.discovery", "permission.hosts.reachability", "ssh.legacy_algorithms"} {
		if !settingsSeen[want] {
			t.Errorf("D-01 setting %s not materialised: %+v", want, m.report.MaterialisedSettings)
		}
	}
	o := m1Options(t, dir, M1{})
	if again, err := startClosed(o); err != nil || again.State != S2 {
		t.Fatalf("second start: %+v, %v", again, err)
	}
}

// E01, E02, A04: every account signs in with its manifest password
// through the Go provider, the locked account is refused, the 72-byte
// password works and 73 bytes do not; fields and namespaces equal the
// manifest.
func TestM1GoldenAccounts(t *testing.T) {
	t.Parallel()
	dir := copyGolden(t)
	m := migrateM1(t, dir, golden.manifest.SecretKey.Value, M1{AdminUsers: []string{"cfg_admin"}})
	acc := &accounts.Service{DB: m.db}
	hasher, err := local.NewHasher(local.Params{Memory: 64, Time: 1, Threads: 1, KeyLen: 32, SaltLen: 16}, 2)
	if err != nil {
		t.Fatal(err)
	}
	provider := &local.Provider{DB: m.db, Accounts: acc, Hasher: hasher}
	for name, want := range golden.manifest.Values.Users {
		t.Run(name, func(t *testing.T) {
			got, err := acc.Get(t.Context(), want.ID)
			if err != nil {
				t.Fatal(err)
			}
			if got.Username != name || got.IsAdmin != want.IsAdmin || got.IsLocked != want.IsLocked ||
				got.MFARequired != want.MFAEnabled || got.AuthGeneration != want.AuthGeneration {
				t.Fatalf("account %+v, manifest %+v", got, want)
			}
			if scope := m.ring.BrowserScope(got.ID, got.Username, got.HistoryGeneration); scope != want.ConnectionHistoryScope {
				t.Fatalf("A04 scope %s, want %s", scope, want.ConnectionHistoryScope)
			}
			if want.Password == nil || got.Managed != accounts.ManagedLocal {
				return
			}
			id, err := provider.Authenticate(t.Context(), name, *want.Password)
			if want.IsLocked {
				if err == nil {
					t.Fatal("the locked account signed in")
				}
				return
			}
			if err != nil || id != want.ID {
				t.Fatalf("sign-in: %d, %v", id, err)
			}
			if _, err := provider.Authenticate(t.Context(), name, *want.Password+"wrong"); err == nil {
				t.Fatal("a wrong password signed in")
			}
			// D-12: the first sign-in replaced the bcrypt hash with Argon2id,
			// and the password still works.
			var algorithm string
			_ = m.db.Read(t.Context(), func(tx *store.Tx) error {
				var err error
				algorithm, _, _, err = local.StoredTx(t.Context(), tx, want.ID)
				return err
			})
			if algorithm != local.AlgorithmArgon2id {
				t.Fatalf("after the first sign-in: %s", algorithm)
			}
			if id, err := provider.Authenticate(t.Context(), name, *want.Password); err != nil || id != want.ID {
				t.Fatalf("sign-in after the rehash: %v", err)
			}
		})
	}
	limit := goldenUserByName(t, "limit_user")
	if _, err := provider.Authenticate(t.Context(), "limit_user", *limit.Password+"x"); err == nil {
		t.Fatal("73 bytes signed in on a bcrypt hash")
	}
	err = m.db.Read(t.Context(), func(tx *store.Tx) error {
		floor, err := accounts.IDFloorTx(t.Context(), tx)
		if err == nil && floor < 12 {
			t.Errorf("id floor %d", floor)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

// E08, E11: the TOTP code of the manifest's activation step is a replay
// and refused, the next step's code is accepted once; each remaining
// recovery code works once and the consumed code never.
func TestM1GoldenFactors(t *testing.T) {
	t.Parallel()
	dir := copyGolden(t)
	m := migrateM1(t, dir, golden.manifest.SecretKey.Value, M1{})
	facts := golden.manifest.Values.TOTP
	user := goldenUserByName(t, "totp_user").ID
	key, err := otp.DecodeSecret(facts.SecretBase32)
	if err != nil {
		t.Fatal(err)
	}
	at := func(step uint64) func() time.Time {
		return func() time.Time { return time.Unix(int64(step*30)+1, 0) } // #nosec G115 -- test steps are small
	}
	svc := &totp.Service{DB: m.db, Ring: m.ring, Now: at(facts.ActivationStep)}
	if ok, err := svc.VerifyCode(t.Context(), user, facts.ActivationCode); err != nil || ok {
		t.Fatalf("replay of the activation code: %v, %v", ok, err)
	}
	next, _ := otp.TOTP(key, facts.ActivationStep+1)
	svc.Now = at(facts.ActivationStep + 1)
	if ok, err := svc.VerifyCode(t.Context(), user, next); err != nil || !ok {
		t.Fatalf("next code: %v, %v", ok, err)
	}
	if ok, _ := svc.VerifyCode(t.Context(), user, next); ok {
		t.Fatal("the same step was accepted twice")
	}
	if ok, _ := svc.VerifyCode(t.Context(), goldenUserByName(t, "local_user").ID, next); ok {
		t.Fatal("another account accepted the code")
	}
	rc := &auth.Recovery{DB: m.db}
	codes := golden.manifest.Values.EdgeCases.RecoveryCode
	owner := recoveryOwner(t, m, codes.Remaining[0])
	for _, code := range codes.Remaining {
		if ok, err := rc.Consume(t.Context(), owner, code); err != nil || !ok {
			t.Fatalf("remaining code %s: %v, %v", code, ok, err)
		}
		if ok, _ := rc.Consume(t.Context(), owner, code); ok {
			t.Fatalf("code %s accepted twice", code)
		}
	}
	if ok, _ := rc.Consume(t.Context(), owner, codes.Consumed); ok {
		t.Fatal("the consumed code was accepted")
	}
}

// recoveryOwner finds the account whose stored hashes hold code.
func recoveryOwner(t *testing.T, m migrated, code string) int64 {
	t.Helper()
	want := RecoveryCodeHash(code)
	for _, u := range golden.manifest.Values.Users {
		var found bool
		_ = m.db.Read(t.Context(), func(tx *store.Tx) error {
			hashes, err := auth.RecoveryHashesTx(t.Context(), tx, u.ID)
			found = slices.ContainsFunc(hashes, func(h []byte) bool { return string(h) == string(want) })
			return err
		})
		if found {
			return u.ID
		}
	}
	t.Fatal("no account holds the recovery code")
	return 0
}

// E23, E17, E24: every stored key yields its manifest public key through
// the vault's signer, the plaintext legacy key is sealed and usable; the
// global key is trusted for everyone, the revoked key refused, user keys
// trusted for their owner only.
func TestM1GoldenKeysAndHostTrust(t *testing.T) {
	t.Parallel()
	dir := copyGolden(t)
	m := migrateM1(t, dir, golden.manifest.SecretKey.Value, M1{})
	v, err := vault.New(vault.Options{DB: m.db, Sealer: m.ring, StepUp: &principaltest.StepUp{}, Limits: vault.Limits{MaxRecords: 100, MaxStoreBytes: 1 << 20}})
	if err != nil {
		t.Fatal(err)
	}
	keys := append(slices.Clone(golden.manifest.Values.SSHKeys.Stored), golden.manifest.Values.SSHKeys.LegacyPlaintext)
	owner := goldenUserByName(t, "local_user").ID
	for _, k := range keys {
		var keyOwner int64
		if _, err := fmt.Sscanf(k.StoredFile, "users/user_%d/", &keyOwner); err != nil {
			t.Fatalf("%s: %v", k.StoredFile, err)
		}
		signer, err := v.Signer(t.Context(), keyOwner, k.KeyID)
		if err != nil {
			t.Fatalf("%s: %v", k.Label, err)
		}
		if k.PublicKeyOpenSSH != "" && strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))) != strings.Join(strings.Fields(k.PublicKeyOpenSSH)[:2], " ") {
			t.Errorf("%s: public key differs", k.Label)
		}
		sig, err := signer.Sign(nil, []byte("challenge"))
		if err != nil || signer.PublicKey().Verify([]byte("challenge"), sig) != nil {
			t.Errorf("%s: cannot sign: %v", k.Label, err)
		}
	}
	// One warning per sealed key; the audit event reports its count (R2 I-3).
	if w := m.entity(t, "E23").Warnings; len(w) != 1 || w[0].Code != "plaintext_key_sealed" || w[0].Count != 1 {
		t.Errorf("E23 warnings %+v", w)
	}
	trust := hostkey.New(m.db, nil)
	global := golden.manifest.Values.HostKeys.GlobalLines
	trusted, revoked := parseLine(t, global[0]), parseLine(t, global[1])
	for _, user := range []int64{owner, goldenUserByName(t, "golden_admin").ID} {
		if ok, err := trust.Known(t.Context(), user, "bastion.golden.test", 22, trusted); err != nil || !ok {
			t.Errorf("global key for user %d: %v, %v", user, ok, err)
		}
		if ok, err := trust.Known(t.Context(), user, "compromised.golden.test", 22, revoked); err == nil || ok {
			t.Errorf("revoked key accepted for user %d", user)
		}
	}
	raw := userKnownHosts(t, dir, owner)
	deleted := golden.manifest.Values.EdgeCases.HostKeyDeleted.DeletedHost
	for _, e := range golden.manifest.Values.HostKeys.UserEntries {
		if e.Host == deleted {
			continue // deleted in Python before the fixture was taken
		}
		key := keyByFingerprint(t, raw, e.Fingerprint)
		host, port := hostkey.HostPort(e.Host)
		if ok, err := trust.Known(t.Context(), owner, host, port, key); err != nil || !ok {
			t.Errorf("%s for its owner: %v, %v", e.Host, ok, err)
		}
		if ok, err := trust.Known(t.Context(), goldenUserByName(t, "golden_admin").ID, host, port, key); err != nil || ok {
			t.Errorf("%s trusted for another user: %v, %v", e.Host, ok, err)
		}
	}
}

func parseLine(t *testing.T, line string) ssh.PublicKey {
	t.Helper()
	f := strings.Fields(line)
	if strings.HasPrefix(f[0], "@") {
		f = f[1:]
	}
	blob, err := base64.StdEncoding.DecodeString(f[2])
	if err != nil {
		t.Fatal(err)
	}
	k, err := ssh.ParsePublicKey(blob)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func userKnownHosts(t *testing.T, dir string, user int64) []HostKey {
	t.Helper()
	src, err := Open(t.Context(), dir, golden.manifest.SecretKey.Value)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	keys, err := src.UserHostKeys(user)
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

func keyByFingerprint(t *testing.T, keys []HostKey, fp string) ssh.PublicKey {
	t.Helper()
	for _, k := range keys {
		if k.Fingerprint == fp {
			return k.Key
		}
	}
	t.Fatalf("no key %s", fp)
	return nil
}

// E19 to E21, A06, A11, E25, A05, E28: saved hosts come back byte for
// byte, the Unicode and long names unchanged; settings, notes and the
// host context notes are stored.
func TestM1GoldenHostsAndSettings(t *testing.T) {
	t.Parallel()
	dir := copyGolden(t)
	m := migrateM1(t, dir, golden.manifest.SecretKey.Value, M1{})
	owner := goldenUserByName(t, "local_user").ID
	var got hosts.Legacy
	err := m.db.Read(t.Context(), func(tx *store.Tx) error {
		var err error
		got, err = hosts.Export(t.Context(), tx, owner)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	src, err := Open(t.Context(), dir, golden.manifest.SecretKey.Value)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	doc, _, err := userStore(src, owner, "profiles")
	if err != nil {
		t.Fatal(err)
	}
	want, _ := doc.RawList("profiles")
	if !sameRecords(got.Profiles, want) || len(got.Profiles) == 0 {
		t.Fatalf("profiles differ:\n%s\n%s", got.Profiles, want)
	}
	edges := golden.manifest.Values.EdgeCases.Profiles
	text := string(joinValues(got.Profiles))
	for _, name := range []string{edges.Unicode, edges.StoredLongName, edges.Minimal} {
		if name != "" && !strings.Contains(text, name) {
			t.Errorf("profile %q missing", name)
		}
	}
	if edges.Deleted != "" && strings.Contains(text, edges.Deleted) {
		t.Errorf("deleted profile %q present", edges.Deleted)
	}
	if len(got.JumpHosts) != 1 || len(got.SOCKSProxies) != 2 {
		t.Errorf("jump hosts %d, proxies %d", len(got.JumpHosts), len(got.SOCKSProxies))
	}
	if e := m.entity(t, "E28"); e.Written != 1 {
		t.Errorf("E28 %+v", e)
	}
}

func joinValues[T ~[]byte](vs []T) []byte {
	var out []byte
	for _, v := range vs {
		out = append(out, v...)
	}
	return out
}

// A dry run on the golden data set completes and writes nothing.
func TestM1DryRunGolden(t *testing.T) {
	t.Parallel()
	dir := copyGolden(t)
	before := legacySnapshot(t, dir)
	rep, err := DryRun(context.Background(), m1Options(t, dir, M1{}))
	if err != nil || rep.Result != ResultDryRun {
		t.Fatalf("%+v, %v", rep, err)
	}
	assertUntouched(t, dir, before)
	if _, err := filepath.Glob(filepath.Join(dir, keyring.GoDirName, keyring.DatabaseName)); err != nil {
		t.Fatal(err)
	}
}
