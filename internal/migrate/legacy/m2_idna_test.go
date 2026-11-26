package legacy

import (
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/bifrost0x/webssh/internal/netpolicy"
	"github.com/bifrost0x/webssh/internal/ssh/hostkey"
	"github.com/bifrost0x/webssh/internal/store"
)

// A saved host with an internationalized name was flagged in M1 because
// Go had no IDNA 2003 conversion. Now it is migrated unflagged, and the
// host key Python stored under the converted name
// ('Bücher.Golden.Test'.encode('idna').lower(), computed with the Python
// release) is found under the name Go derives from the saved host.
func TestM2InternationalizedHostKeepsItsHostKey(t *testing.T) {
	t.Parallel()
	const host, pythonName = "Bücher.Golden.Test", "xn--bcher-kva.golden.test"
	dir := copyGolden(t)
	replaceIn(t, filepath.Join(dir, "users", "user_3", "profiles.json"), `"host": "pw.golden.test"`, `"host": "`+host+`"`)
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	appendTo(t, filepath.Join(dir, "users", "user_3", "known_hosts"), hostkey.FormatLine(pythonName, key))
	m := migrateM1(t, dir, golden.manifest.SecretKey.Value, M1{})
	for _, f := range m.entity(t, "E19").Flagged {
		if strings.Contains(f.Reason, "idna") {
			t.Fatalf("internationalized host still flagged: %+v", f)
		}
	}
	var stored string
	if err := m.db.Read(t.Context(), func(tx *store.Tx) error {
		return tx.QueryRowContext(t.Context(), `SELECT "host" FROM hosts_profiles WHERE user_id = 3 AND position = 0`).Scan(&stored)
	}); err != nil {
		t.Fatal(err)
	}
	if stored != `"`+host+`"` {
		t.Fatalf("stored host %s", stored)
	}
	canonical, err := netpolicy.CanonicalHost(host)
	if err != nil || canonical != pythonName {
		t.Fatalf("canonical %q, %v; Python %q", canonical, err, pythonName)
	}
	if ok, err := hostkey.New(m.db, nil).Known(t.Context(), 3, canonical, 22, key); err != nil || !ok {
		t.Fatalf("host key under the converted name: %v, %v", ok, err)
	}
}
