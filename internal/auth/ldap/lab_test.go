//go:build lab

// The lab tests run the directory client against the OpenLDAP servers of
// the shared test lab (tests/lab). Run them with
//
//	WEBSSH_LAB_JSON=…/tests/lab/runtime/lab.json go test -tags lab -run Lab ./internal/auth/ldap
//
// They fail, not skip, when the lab is not reachable: a lab run that tested
// nothing must not look green.
package ldap

import (
	"context"
	"crypto/x509"
	json "encoding/json/v2"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/ldapproto"
	"github.com/bifrost0x/webssh/internal/store"
)

type labFile struct {
	RuntimeDir string `json:"runtime_dir"`
	CAFile     string `json:"ca_file"`
}

var loadLab = sync.OnceValues(func() (labFile, error) {
	path := os.Getenv("WEBSSH_LAB_JSON")
	if path == "" {
		path = filepath.Join("..", "..", "..", "tests", "lab", "runtime", "lab.json")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return labFile{}, err
	}
	var l labFile
	if err := json.Unmarshal(raw, &l, json.RejectUnknownMembers(false)); err != nil {
		return labFile{}, err
	}
	return l, nil
})

func lab(t *testing.T) labFile {
	t.Helper()
	l, err := loadLab()
	if err != nil {
		t.Fatalf("lab inventory: %v (set WEBSSH_LAB_JSON)", err)
	}
	return l
}

func (l labFile) path(rel string) string { return filepath.Join(l.RuntimeDir, rel) }

func (l labFile) secret(t *testing.T, rel string) string {
	t.Helper()
	raw, err := os.ReadFile(l.path(rel))
	if err != nil {
		t.Fatal(err)
	}
	line, _, _ := strings.Cut(string(raw), "\n")
	return strings.TrimRight(line, "\r")
}

// secretCopy copies a lab secret into a 0600 file: the lab writes them
// with 0644, which the secret rules refuse.
func (l labFile) secretCopy(t *testing.T, rel string) string {
	t.Helper()
	return writeFile(t, t.TempDir(), "secret", l.secret(t, rel)+"\n", 0o600)
}

// labDialer maps in-network lab names to the host ports, so that a name
// such as ldap2.lab.test resolves while TLS still verifies it, and counts
// the connections per name.
type labDialer struct {
	dials sync.Map // address -> *atomic.Int32
}

func (d *labDialer) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	n, _ := d.dials.LoadOrStore(addr, new(atomic.Int32))
	n.(*atomic.Int32).Add(1)
	mapped := map[string]string{
		"ldap1.lab.test:389": "127.0.0.1:13389",
		"ldap2.lab.test:389": "127.0.0.1:13390",
		"wrong.lab.test:389": "127.0.0.1:13389",
	}
	if m, ok := mapped[addr]; ok {
		addr = m
	}
	return (&net.Dialer{}).DialContext(ctx, network, addr)
}

func (d *labDialer) count(addr string) int32 {
	if n, ok := d.dials.Load(addr); ok {
		return n.(*atomic.Int32).Load()
	}
	return 0
}

const aliceSubject = "afc8b795-5c9d-454c-988a-bd4184efdb5e"

func labSettings(t *testing.T, l labFile, d *labDialer) Settings {
	t.Helper()
	return Settings{
		Provider: "lab", URL: "ldap://127.0.0.1:13389", BaseDN: "dc=lab,dc=test",
		BindDN: "cn=webssh,ou=services,dc=lab,dc=test", BindPasswordFile: l.secretCopy(t, "secrets/ldap-bind-webssh"),
		CAFile: l.path(l.CAFile), UserFilter: "(&(objectClass=inetOrgPerson)(uid={username}))",
		UniqueIDAttribute: "entryUUID", ConnectTimeout: 2 * time.Second, OperationTimeout: 2 * time.Second, Dial: d.dial,
	}
}

func mustClient(t *testing.T, s Settings) *Client {
	t.Helper()
	c, err := NewClient(s)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Ready(); err != nil {
		t.Fatalf("ready: %v", err)
	}
	return c
}

func TestLabStartTLSLookupAndBind(t *testing.T) {
	l := lab(t)
	for _, url := range []string{"ldap://127.0.0.1:13389", "ldap://localhost:13389", "ldaps://127.0.0.1:13636", "ldap://ldap1.lab.test:389"} {
		t.Run(url, func(t *testing.T) {
			s := labSettings(t, l, &labDialer{})
			s.URL = url
			c := mustClient(t, s)
			ctx := t.Context()
			e, err := c.Lookup(ctx, " alice ")
			if err != nil {
				t.Fatal(err)
			}
			if e.Subject != aliceSubject || e.DN != "uid=alice,ou=people,dc=lab,dc=test" {
				t.Fatalf("unexpected entry %+v", e)
			}
			if ok, err := c.VerifyPassword(ctx, e.DN, l.secret(t, "secrets/ldap-alice")); err != nil || !ok {
				t.Fatalf("correct password: ok=%v err=%v", ok, err)
			}
			for _, wrong := range []string{"wrong", l.secret(t, "secrets/ldap-bob"), ""} {
				if ok, err := c.VerifyPassword(ctx, e.DN, wrong); err != nil || ok {
					t.Fatalf("wrong password %q accepted: ok=%v err=%v", wrong, ok, err)
				}
			}
			if err := c.Probe(ctx); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestLabFilters(t *testing.T) {
	l := lab(t)
	for _, tc := range []struct {
		filter, name string
		want         error
	}{
		{"uid={username}", "alice", nil},                                     // no parentheses, as libldap accepts
		{"(& (objectClass=inetOrgPerson) (uid={username}))", "alice", nil},   // white space between members
		{"(|(uid={username})(uid=bob))", "alice", ErrRejected},               // two entries
		{"(|(uid={username})(objectClass=*))", "alice", ErrRejected},         // size limit exceeded
		{"(&(uid={username})", "alice", ErrUnavailable},                      // does not compile
		{"(&(objectClass=inetOrgPerson)(uid={username}))", "*", ErrRejected}, // escaped, no wildcard
		{"(&(objectClass=inetOrgPerson)(uid={username}))", "alice)(uid=*", ErrRejected},
		{"(&(objectClass=inetOrgPerson)(uid={username}))", "a*", ErrRejected},
		{"(&(objectClass=inetOrgPerson)(uid={username}))", "nobody", ErrRejected},
		{"(&(objectClass=inetOrgPerson)(uid={username}))", "carol", ErrRejected}, // behind a referral
	} {
		t.Run(tc.filter+" "+tc.name, func(t *testing.T) {
			s := labSettings(t, l, &labDialer{})
			s.UserFilter = tc.filter
			c, err := NewClient(s)
			if err != nil {
				t.Fatal(err)
			}
			e, err := c.Lookup(t.Context(), tc.name)
			if tc.want == nil && (err != nil || e.Subject != aliceSubject) || tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("got %+v %v, want %v", e, err, tc.want)
			}
		})
	}
	t.Run("missing unique attribute", func(t *testing.T) {
		s := labSettings(t, l, &labDialer{})
		s.UniqueIDAttribute = "employeeNumber"
		if _, err := mustClient(t, s).Lookup(t.Context(), "alice"); !errors.Is(err, ErrRejected) {
			t.Fatalf("want ErrRejected, got %v", err)
		}
	})
}

func TestLabCertificatePolicy(t *testing.T) {
	l := lab(t)
	foreign := writeFile(t, t.TempDir(), "foreign.pem", testCA(t), 0o644)
	cases := []struct {
		name   string
		mutate func(*Settings)
		check  func(error) bool
	}{
		{"foreign CA via StartTLS", func(s *Settings) { s.CAFile = foreign },
			func(err error) bool { _, ok := errors.AsType[x509.UnknownAuthorityError](err); return ok }},
		{"foreign CA via LDAPS", func(s *Settings) { s.CAFile = foreign; s.URL = "ldaps://127.0.0.1:13636" },
			func(err error) bool { _, ok := errors.AsType[x509.UnknownAuthorityError](err); return ok }},
		{"host name not in certificate", func(s *Settings) { s.URL = "ldap://wrong.lab.test:389" },
			func(err error) bool { _, ok := errors.AsType[x509.HostnameError](err); return ok }},
		{"wrong service password", func(s *Settings) { s.BindPasswordFile = writeFile(t, t.TempDir(), "pw", "nope", 0o600) },
			func(error) bool { return true }},
		{"world-readable secret", func(s *Settings) { s.BindPasswordFile = l.path("secrets/ldap-bind-webssh") },
			func(error) bool { return true }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := labSettings(t, l, &labDialer{})
			tc.mutate(&s)
			c, err := NewClient(s)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := c.Lookup(t.Context(), "alice"); !errors.Is(err, ErrUnavailable) || !tc.check(err) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

// TestLabReferralWithResolvableTarget is condition K7: the directory
// names a referral target that resolves and presents a valid
// certificate (ldap2), and the client still sends nothing there, neither
// the service password nor the user's.
func TestLabReferralWithResolvableTarget(t *testing.T) {
	l := lab(t)
	d := &labDialer{}
	s := labSettings(t, l, d)
	c := mustClient(t, s)
	ctx := t.Context()
	pool, err := loadCA(s.CAFile)
	if err != nil {
		t.Fatal(err)
	}
	// The target is reachable and trusted: a direct connection works.
	u, _ := ldapproto.ParseServerURL("ldap://ldap2.lab.test:389")
	conn, err := ldapproto.Dial(ctx, ldapproto.Config{URL: u, RootCAs: pool, Dial: (&labDialer{}).dial})
	if err != nil {
		t.Fatalf("ldap2 must be reachable for this test: %v", err)
	}
	_ = conn.Close()
	if _, err := c.Lookup(ctx, "carol"); !errors.Is(err, ErrRejected) {
		t.Fatalf("continuation reference: want ErrRejected, got %v", err)
	}
	if d.count("ldap2.lab.test:389") != 0 {
		t.Fatal("the client followed the referral")
	}
	// A base below the referral is answered with a referral result: no
	// verdict, so the directory counts as unavailable (D-K7-01).
	s.BaseDN = "ou=partners,dc=lab,dc=test"
	if _, err := mustClient(t, s).Lookup(ctx, "carol"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("base below a referral: want ErrUnavailable, got %v", err)
	}
	if d.count("ldap2.lab.test:389") != 0 {
		t.Fatal("the client followed the referral result")
	}
	if e, err := c.Lookup(ctx, "alice"); err != nil || e.Subject != aliceSubject {
		t.Fatalf("alice must still resolve: %v", err)
	}
}

func TestLabTimeoutsAndFailover(t *testing.T) {
	l := lab(t)
	for _, tc := range []struct{ name, url string }{
		{"slow server", "ldap://127.0.0.1:13391"},
		{"black hole", "ldap://127.0.0.1:13392"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := labSettings(t, l, &labDialer{})
			s.URL, s.ConnectTimeout, s.OperationTimeout = tc.url, time.Second, time.Second
			start := time.Now()
			_, err := mustClient(t, s).Lookup(t.Context(), "alice")
			elapsed := time.Since(start)
			if !errors.Is(err, ErrUnavailable) || !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("want deadline-based ErrUnavailable, got %v", err)
			}
			if elapsed < 900*time.Millisecond || elapsed > 1500*time.Millisecond {
				t.Fatalf("timeout took %v, want about 1s", elapsed)
			}
		})
	}
	t.Run("failover to backup and stick", func(t *testing.T) {
		s := labSettings(t, l, &labDialer{})
		s.URL, s.BackupURL, s.ConnectTimeout = "ldap://127.0.0.1:13392", "ldaps://127.0.0.1:13636", time.Second
		c := mustClient(t, s)
		start := time.Now()
		if _, err := c.Lookup(t.Context(), "alice"); err != nil {
			t.Fatal(err)
		}
		first := time.Since(start)
		start = time.Now()
		if _, err := c.Lookup(t.Context(), "alice"); err != nil {
			t.Fatal(err)
		}
		if second := time.Since(start); first < 900*time.Millisecond || second > 500*time.Millisecond {
			t.Fatalf("first %v, second %v", first, second)
		}
		if ok, err := c.VerifyPassword(t.Context(), "uid=alice,ou=people,dc=lab,dc=test", l.secret(t, "secrets/ldap-alice")); !ok || err != nil {
			t.Fatalf("bind on the backup: %v %v", ok, err)
		}
	})
	t.Run("caller cancellation", func(t *testing.T) {
		s := labSettings(t, l, &labDialer{})
		s.URL, s.ConnectTimeout = "ldap://127.0.0.1:13392", 10*time.Second
		ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
		defer cancel()
		start := time.Now()
		if _, err := mustClient(t, s).Lookup(ctx, "alice"); !errors.Is(err, ErrUnavailable) || time.Since(start) > time.Second {
			t.Fatalf("cancellation not honoured: %v after %v", err, time.Since(start))
		}
	})
}

// TestLabService signs in through the service with the real directory:
// a linked identity resolves to its account, auto-provisioning creates
// one, revalidation passes and the step-up proof works.
func TestLabService(t *testing.T) {
	l := lab(t)
	f := newFixture(t)
	f.svc.Provider = "lab"
	f.svc.Directory = mustClient(t, labSettings(t, l, &labDialer{}))
	f.now = time.Now().UTC()
	f.accounts.add(Account{ID: 7, Username: "alice", Managed: "ldap"})
	if err := f.svc.DB.Write(t.Context(), func(tx *store.Tx) error {
		_, err := insertIdentityTx(t.Context(), tx, Identity{UserID: 7, Provider: "lab", Subject: aliceSubject,
			DirectoryUsername: "alice", DistinguishedName: "uid=alice,ou=people,dc=lab,dc=test", CreatedAt: f.now})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	if id, err := f.svc.Authenticate(ctx, "alice", l.secret(t, "secrets/ldap-alice")); err != nil || id != 7 {
		t.Fatalf("alice: %d %v", id, err)
	}
	if _, err := f.svc.Authenticate(ctx, "alice", "wrong"); !fault.Is(err, fault.AuthFailed) {
		t.Fatalf("wrong password: %v", err)
	}
	if _, err := f.svc.Authenticate(ctx, "bob", l.secret(t, "secrets/ldap-bob")); !fault.Is(err, fault.AuthFailed) {
		t.Fatalf("unlinked bob without auto-provisioning: %v", err)
	}
	f.svc.AutoProvision = true
	bob, err := f.svc.Authenticate(ctx, "bob", l.secret(t, "secrets/ldap-bob"))
	if err != nil || f.accounts.get(bob).Username != "bob" {
		t.Fatalf("provisioned bob: %d %v", bob, err)
	}
	f.now = f.now.Add(time.Hour)
	if err := f.svc.Revalidate(ctx, 7); err != nil {
		t.Fatalf("revalidate: %v", err)
	}
	if ok, err := f.svc.VerifyStepUp(ctx, 7, l.secret(t, "secrets/ldap-alice")); !ok || err != nil {
		t.Fatalf("step-up: %v %v", ok, err)
	}
	if n, err := f.svc.Sweep(ctx); err != nil || n != 0 {
		t.Fatalf("sweep: %d %v", n, err)
	}
}
