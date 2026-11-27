package legacy

import (
	"context"
	"crypto/rand"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"os"
	"slices"
	"testing"

	"github.com/bifrost0x/webssh/internal/accounts"
	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/hosts"
	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/principal/principaltest"
	"github.com/bifrost0x/webssh/internal/store"
	"github.com/bifrost0x/webssh/internal/store/storetest"
	"github.com/bifrost0x/webssh/internal/vault"
)

// migratedStores provides the migrated saved hosts, jump hosts and
// proxies to the vault, as cmd/webssh does over internal/hosts.
type migratedStores struct{ db *store.DB }

func (m migratedStores) Records(ctx context.Context, userID int64) (vault.Records, error) {
	var l hosts.Legacy
	err := m.db.Read(ctx, func(tx *store.Tx) error {
		var err error
		l, err = hosts.Export(ctx, tx, userID)
		return err
	})
	return vault.Records{Profiles: l.Profiles, JumpHosts: l.JumpHosts, SOCKSProxies: l.SOCKSProxies}, err
}

type enabledPolicy struct{}

func (enabledPolicy) CredentialsPolicy(context.Context) (bool, string, error) { return true, "", nil }

type migratedIncarnations struct{ acc *accounts.Service }

func (m migratedIncarnations) Incarnation(ctx context.Context, id int64) (string, error) {
	a, err := m.acc.Get(ctx, id)
	return a.Incarnation, err
}

func credentialsRegistry(t *testing.T) *Registry {
	t.Helper()
	r := m1Registry(t, M1{AdminUsers: []string{"cfg_admin"}, Persistent: &testPersistent{}})
	if err := AddCredentials(r); err != nil {
		t.Fatal(err)
	}
	return r
}

func migrateCredentials(t *testing.T, dir, secret string) (migrated, *vault.Service, *principaltest.StepUp) {
	t.Helper()
	before := legacySnapshot(t, dir)
	o := testOptions(t, dir)
	o.Registry = credentialsRegistry(t)
	o.Secret = secret
	st, err := startClosed(o)
	if err != nil || !st.Migrated {
		t.Fatalf("migration: %+v, %v", st, err)
	}
	assertUntouched(t, dir, before)
	m := openMigrated(t, dir, secret, st.Report)
	steps := &principaltest.StepUp{}
	svc, err := vault.New(vault.Options{DB: m.db, Sealer: m.ring, StepUp: steps, Limits: vault.Limits{MaxRecords: 100, MaxStoreBytes: 8 << 20}})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.EnableCredentials(vault.CredentialOptions{Stores: migratedStores{m.db}, Policy: enabledPolicy{},
		Accounts: migratedIncarnations{&accounts.Service{DB: m.db}}}); err != nil {
		t.Fatal(err)
	}
	return m, svc, steps
}

func resourceTarget(t *testing.T, svc *vault.Service, userID int64, id string) vault.Target {
	t.Helper()
	tgt, found, err := svc.Resource(t.Context(), userID, id)
	if err != nil || !found {
		t.Fatalf("resource %s: %v %v", id, found, err)
	}
	return tgt
}

func credentialState(t *testing.T, svc *vault.Service, p principal.Principal) (names []string, status map[string]string, legacyWaiting bool) {
	t.Helper()
	raw, err := svc.State(principal.With(t.Context(), p))
	if err != nil {
		t.Fatal(err)
	}
	var st struct {
		Credentials []struct {
			Name string `json:"name"`
		} `json:"credentials"`
		Profiles []struct {
			ID     string `json:"id"`
			Status string `json:"credential_status"`
		} `json:"profiles"`
		Legacy bool `json:"legacy_vault"`
	}
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatal(err)
	}
	status = map[string]string{}
	for _, c := range st.Credentials {
		names = append(names, c.Name)
	}
	for _, p := range st.Profiles {
		status[p.ID] = p.Status
	}
	return names, status, st.Legacy
}

// importLegacy prepares and applies the import of the legacy vault as
// the page does, with a fresh step-up grant.
func importLegacy(t *testing.T, svc *vault.Service, steps *principaltest.StepUp, p principal.Principal, passphrase string) error {
	t.Helper()
	ctx := principal.With(t.Context(), p)
	mutation, _ := json.Marshal(map[string]any{"method": "import", "passphrase": passphrase})
	out, err := svc.Prepare(ctx, jsontext.Value(`{"operation":"native","mutation":`+string(mutation)+`}`))
	if err != nil {
		return err
	}
	var in struct {
		Intent string `json:"intent"`
	}
	_ = json.Unmarshal(out, &in)
	grant := "grant-" + in.Intent[:8]
	steps.Issue(p, principal.ActionCredentialsVault, in.Intent, grant)
	body, _ := json.Marshal(map[string]any{"intent": in.Intent, "passphrase": passphrase})
	_, err = svc.Apply(ctx, vault.MethodImport, "", body, grant)
	return err
}

// E32 and E30 on the golden data set: every password equals the manifest
// (the 4096-byte Unicode one included) and reaches its saved host through
// the vault; the kept vault imports with the manifest passphrase into three
// passwords, and a wrong passphrase changes nothing.
func TestCredentialsMigrateGolden(t *testing.T) {
	t.Parallel()
	dir := copyGolden(t)
	m, svc, steps := migrateCredentials(t, dir, golden.manifest.SecretKey.Value)
	for _, p := range m.report.Pending {
		if p.Entity == "E32" || p.Entity == "E30" {
			t.Errorf("%s still pending", p.Entity)
		}
	}
	if e := m.entity(t, "E32"); e.Read != 2 || e.Written != 2 {
		t.Errorf("E32 report %+v", e)
	}
	owner := goldenUserByName(t, "local_user").ID
	if e := m.entity(t, "E30"); e.Written != 1 || !slices.Contains(e.UserActions, UserAction{UserID: owner, Action: "import_legacy_automation_vault"}) {
		t.Errorf("E30 report %+v", e)
	}
	v := golden.manifest.Values
	err := m.db.Read(t.Context(), func(tx *store.Tx) error {
		got, _, _, err := vault.ExportCredentialsTx(t.Context(), tx, m.ring, owner)
		if err != nil {
			return err
		}
		for _, want := range []goldenCredential{v.NamedCredential, v.EdgeCases.NamedCredentials.UnassignedUnicode} {
			i := slices.IndexFunc(got, func(c vault.ExportedCredential) bool { return c.ID == want.RecordID })
			if i < 0 || string(got[i].Password) != want.Password {
				t.Errorf("credential %s differs from the manifest", want.RecordID)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if n := len(v.EdgeCases.NamedCredentials.UnassignedUnicode.Password); n != 4096 {
		t.Errorf("the Unicode password has %d bytes", n)
	}
	rid := v.NamedCredential.ResourceID
	secret, err := svc.Password(t.Context(), owner, rid, resourceTarget(t, svc, owner, rid))
	if err != nil || string(secret) != v.NamedCredential.Password {
		t.Fatalf("assigned password through the vault: %v", err)
	}
	p := principaltest.User(owner)
	names, status, waiting := credentialState(t, svc, p)
	if status[rid] != "ready" || len(names) != 2 || !waiting {
		t.Fatalf("state after migration: %v %v legacy %v", names, status[rid], waiting)
	}
	if err := importLegacy(t, svc, steps, p, "a wrong but long passphrase"); err == nil {
		t.Fatal("wrong passphrase imported")
	}
	if again, _, _ := credentialState(t, svc, p); len(again) != 2 {
		t.Fatalf("a failed import changed the passwords: %v", again)
	}
	if err := importLegacy(t, svc, steps, p, v.VaultPassphrase); err != nil {
		t.Fatal(err)
	}
	names, _, waiting = credentialState(t, svc, p)
	if len(names) != 5 || waiting {
		t.Fatalf("after import: %v, legacy offered %v", names, waiting)
	}
	want := map[string]string{v.EdgeCases.VaultLongPassword.ProfileID: v.EdgeCases.VaultLongPassword.Password}
	for _, e := range v.Vault {
		want[e.ProfileID] = e.Password
	}
	// The long password was put into the vault for a host behind a SOCKS
	// proxy, bound without the route as the vault did; Python's import
	// keeps that binding, so the host asks for a review (changed), as it
	// does in the Python release.
	routed := v.EdgeCases.VaultLongPassword.ProfileID
	for id, pw := range want {
		if id == rid {
			continue // already assigned: the import adds the password, the assignment stays
		}
		got, err := svc.Password(t.Context(), owner, id, resourceTarget(t, svc, owner, id))
		if id == routed {
			if codeOfFault(err) != "credential_target_changed" {
				t.Errorf("routed host: %v", err)
			}
			continue
		}
		if err != nil || string(got) != pw {
			t.Errorf("imported password of %s: %v", id, err)
		}
	}
	if _, status, _ := credentialState(t, svc, p); status[routed] != "changed" {
		t.Errorf("routed host status %s", status[routed])
	}
}

func codeOfFault(err error) string {
	if e, ok := fault.From(err); ok {
		return string(e.Code)
	}
	return ""
}

// The extended 3.3.x data set holds a version 1 vault: it is kept and
// imports with its passphrase.
func TestCredentialsMigrateVaultV1(t *testing.T) {
	t.Parallel()
	fx := legacyFixture(t)
	ext := fx.Values.Extended
	dir := extractLegacy(t, "datadir-extended.tar")
	m, svc, steps := migrateCredentials(t, dir, fx.SecretKey.Value)
	err := m.db.Read(t.Context(), func(tx *store.Tx) error {
		_, version, found, err := vault.ExportLegacyVaultTx(t.Context(), tx, ext.VaultV1.UserID)
		if err != nil || !found || version != 1 {
			t.Errorf("kept vault: version %d found %v %v", version, found, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	p := principaltest.User(ext.VaultV1.UserID)
	if err := importLegacy(t, svc, steps, p, ext.VaultV1.Passphrase); err != nil {
		t.Fatal(err)
	}
	id := ext.VaultV1.ProfileID
	got, err := svc.Password(t.Context(), ext.VaultV1.UserID, id, resourceTarget(t, svc, ext.VaultV1.UserID, id))
	if err != nil || string(got) != ext.VaultV1.Password {
		t.Fatalf("v1 password: %v", err)
	}
}

// Verify notices a stored password, assignment or kept vault that
// differs from what was read.
func TestCredentialsVerifyDetectsTampering(t *testing.T) {
	t.Parallel()
	ring := testRing(t)
	for _, tamper := range []string{
		`UPDATE vault_credentials SET name = 'other'`,
		`UPDATE vault_credential_assignments SET fingerprint = 'x'`,
		`DELETE FROM vault_credential_imports`,
		`UPDATE vault_legacy_automation SET document = CAST('{}' AS BLOB)`,
	} {
		db := storetest.Open(t, vault.Schema(), hosts.Schema())
		creds := &credentialsStep{users: []userCredentials{{id: 1,
			creds:       []NamedCredential{{ID: "c1", Name: "n", Version: "v", UpdatedAt: "t", Password: "pw"}},
			assignments: []vault.Assignment{{ResourceID: "p1", CredentialID: "c1", Fingerprint: "f", Generation: "g"}},
			imports:     []string{"r"}, status: map[string]vault.Status{"p1": vault.StatusMissing}}}}
		o := readOracleVault(t)
		vaults := &legacyVaultStep{users: []userVault{{id: 1, version: 2, document: o}}}
		ctx := t.Context()
		if err := db.Write(ctx, func(tx *store.Tx) error {
			return errors.Join(creds.Write(ctx, tx, ring), vaults.Write(ctx, tx, ring))
		}); err != nil {
			t.Fatal(err)
		}
		if err := db.Read(ctx, func(tx *store.Tx) error {
			return errors.Join(creds.Verify(ctx, tx, ring), vaults.Verify(ctx, tx, ring))
		}); err != nil {
			t.Fatalf("untouched: %v", err)
		}
		if err := db.Write(ctx, func(tx *store.Tx) error { _, err := tx.ExecContext(ctx, tamper); return err }); err != nil {
			t.Fatal(err)
		}
		if err := db.Read(ctx, func(tx *store.Tx) error {
			return errors.Join(creds.Verify(ctx, tx, ring), vaults.Verify(ctx, tx, ring))
		}); err == nil {
			t.Errorf("%s: not detected", tamper)
		}
	}
}

// readOracleVault returns the version 2 vault of the Python oracle.
func readOracleVault(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile("../../vault/testdata/credential-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var o struct {
		Vaults []struct {
			Document string `json:"document"`
		} `json:"vaults"`
	}
	if err := json.Unmarshal(raw, &o); err != nil {
		t.Fatal(err)
	}
	return []byte(o.Vaults[1].Document)
}

func testRing(t *testing.T) *keyring.Ring {
	t.Helper()
	material := make([]byte, keyring.MaterialSize)
	if _, err := rand.Read(material); err != nil {
		t.Fatal(err)
	}
	r, err := keyring.Open([]byte("synthetic-test-secret-"+rand.Text()), material)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
