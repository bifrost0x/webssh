package vault

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	json "encoding/json/v2"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/principal/principaltest"
	"github.com/bifrost0x/webssh/internal/store"
	"github.com/bifrost0x/webssh/internal/store/storetest"
)

// goldenPassphrase protects the passphrase keys of the golden data set.
const goldenPassphrase = "golden key passphrase"

type goldenKey struct {
	Label        string `json:"label"`
	Algorithm    string `json:"algorithm"`
	Format       string `json:"format"`
	Protected    bool   `json:"passphrase_protected"`
	Public       string `json:"public_key_openssh"`
	PlaintextB64 string `json:"plaintext_b64"`
	KeyType      string `json:"key_type"`
}

func (k goldenKey) pem(t testing.TB) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(k.PlaintextB64)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func goldenKeys(t testing.TB) (stored, rejected []goldenKey) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "tests", "golden", "fixture", "manifest.json"))
	if err != nil {
		t.Fatalf("golden data set missing: %v", err)
	}
	var m struct {
		Values struct {
			SSHKeys struct {
				Stored   []goldenKey `json:"stored"`
				Rejected []goldenKey `json:"rejected"`
			} `json:"ssh_keys"`
		} `json:"values"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if len(m.Values.SSHKeys.Stored) != 9 {
		t.Fatalf("golden stored keys: %d, want 9", len(m.Values.SSHKeys.Stored))
	}
	return m.Values.SSHKeys.Stored, m.Values.SSHKeys.Rejected
}

func goldenByLabel(t testing.TB, label string) goldenKey {
	t.Helper()
	stored, rejected := goldenKeys(t)
	for _, k := range append(stored, rejected...) {
		if k.Label == label {
			return k
		}
	}
	t.Fatalf("no golden key %q", label)
	return goldenKey{}
}

// newEd25519PEM returns a fresh unencrypted OpenSSH private key.
func newEd25519PEM(t testing.TB) []byte {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(b)
}

func newRing(t testing.TB) *keyring.Ring {
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

type rig struct {
	db     *store.DB
	ring   *keyring.Ring
	stepUp *principaltest.StepUp
	svc    *Service
}

var fixedNow = time.Date(2026, 11, 26, 10, 11, 12, 345678000, time.UTC)

func newRig(t testing.TB, limits Limits) *rig {
	t.Helper()
	r := &rig{db: storetest.Open(t, Schema()), ring: newRing(t), stepUp: &principaltest.StepUp{}}
	if limits == (Limits{}) {
		limits = Limits{MaxRecords: 100, MaxStoreBytes: 8 << 20}
	}
	svc, err := New(Options{DB: r.db, Sealer: r.ring, StepUp: r.stepUp, Limits: limits, Now: func() time.Time { return fixedNow }})
	if err != nil {
		t.Fatal(err)
	}
	r.svc = svc
	return r
}

func as(p principal.Principal) context.Context {
	return principal.With(context.Background(), p)
}

// upload stores content for p with a fresh grant and fails the test on
// error.
func (r *rig) upload(t testing.TB, p principal.Principal, name string, content []byte) Summary {
	t.Helper()
	grant := "grant-" + rand.Text()
	r.stepUp.Issue(p, principal.ActionKeyUpload, userTarget(p), grant)
	s, err := r.svc.Upload(as(p), Upload{Name: name, Content: string(content), Grant: grant})
	if err != nil {
		t.Fatalf("upload %s: %v", name, err)
	}
	return s
}

func (r *rig) grant(p principal.Principal, action principal.Action, target string) string {
	g := "grant-" + rand.Text()
	r.stepUp.Issue(p, action, target, g)
	return g
}
