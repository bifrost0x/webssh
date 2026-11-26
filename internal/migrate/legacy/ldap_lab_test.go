//go:build lab

package legacy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/accounts"
	"github.com/bifrost0x/webssh/internal/auth/ldap"
	"github.com/bifrost0x/webssh/internal/fault"
)

// TestLabMigratedLDAPBindingSignsIn is the functional verification of E03
// against the lab directory (K7): a Python identity bound to alice's
// entryUUID, migrated, signs in through OpenLDAP to the same account.
func TestLabMigratedLDAPBindingSignsIn(t *testing.T) {
	inv := os.Getenv("WEBSSH_LAB_JSON")
	if inv == "" {
		inv = filepath.Join("..", "..", "..", "tests", "lab", "runtime", "lab.json")
	}
	if _, err := os.Stat(inv); err != nil {
		t.Fatalf("lab not available (set WEBSSH_LAB_JSON): %v", err)
	}
	root := filepath.Dir(inv)
	secret := func(name string) string {
		raw, err := os.ReadFile(filepath.Join(root, "secrets", name))
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimRight(strings.SplitN(string(raw), "\n", 2)[0], "\r")
	}
	dir := copyGolden(t)
	execLegacySQL(t, dir, `UPDATE ldap_identities SET provider = 'lab', subject = 'afc8b795-5c9d-454c-988a-bd4184efdb5e',
		directory_username = 'alice', distinguished_name = 'uid=alice,ou=people,dc=lab,dc=test' WHERE id = 1`)
	m := migrateWithLDAP(t, dir, golden.manifest.SecretKey.Value)

	pw := filepath.Join(t.TempDir(), "pw")
	if err := os.WriteFile(pw, []byte(secret("ldap-bind-webssh")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	client, err := ldap.NewClient(ldap.Settings{Provider: "lab", URL: "ldap://127.0.0.1:13389", BaseDN: "dc=lab,dc=test",
		BindDN: "cn=webssh,ou=services,dc=lab,dc=test", BindPasswordFile: pw, CAFile: filepath.Join(root, "ca", "ca.crt"),
		UserFilter: "(&(objectClass=inetOrgPerson)(uid={username}))", UniqueIDAttribute: "entryUUID",
		ConnectTimeout: 3 * time.Second, OperationTimeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	sessions := &countingSessions{}
	svc := &ldap.Service{DB: m.db, Directory: client, Accounts: migratedAccounts{&accounts.Service{DB: m.db}},
		Sessions: sessions, Enabled: true, Provider: "lab", Revalidation: 5 * time.Minute}
	id, err := svc.Authenticate(t.Context(), "alice", secret("ldap-alice"))
	if err != nil || id != goldenLDAPUser {
		t.Fatalf("migrated binding: %d %v", id, err)
	}
	if _, err := svc.Authenticate(t.Context(), "alice", "wrong"); !fault.Is(err, fault.AuthFailed) {
		t.Fatalf("wrong password: %v", err)
	}
	// bob has no binding and LDAP_AUTO_PROVISION is off.
	if _, err := svc.Authenticate(t.Context(), "bob", secret("ldap-bob")); !fault.Is(err, fault.AuthFailed) {
		t.Fatalf("unbound bob: %v", err)
	}
	if err := svc.Revalidate(t.Context(), goldenLDAPUser); err != nil {
		t.Fatalf("revalidation of the migrated account: %v", err)
	}
}
