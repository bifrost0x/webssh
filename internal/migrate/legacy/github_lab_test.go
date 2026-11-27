//go:build lab

package legacy

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	json "encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ncruces/go-sqlite3/driver"

	"github.com/bifrost0x/webssh/internal/accounts"
	"github.com/bifrost0x/webssh/internal/auth"
	"github.com/bifrost0x/webssh/internal/auth/github"
	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/store"
)

// fernetPurposeEncrypt writes a Fernet token as cryptography.Fernet does,
// with the key derivation of purpose.
func fernetPurposeEncrypt(t *testing.T, p fernetPurpose, secret string, plain []byte) []byte {
	t.Helper()
	raw, err := pbkdf2.Key(sha256.New, p.password(secret, 0), []byte(p.salt), pbkdf2Iterations, 32)
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(raw[16:])
	if err != nil {
		t.Fatal(err)
	}
	pad := aes.BlockSize - len(plain)%aes.BlockSize
	padded := append(bytes.Clone(plain), bytes.Repeat([]byte{byte(pad)}, pad)...)
	iv := make([]byte, aes.BlockSize)
	_, _ = rand.Read(iv)
	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)
	msg := []byte{0x80}
	msg = binary.BigEndian.AppendUint64(msg, uint64(time.Now().Unix())) // #nosec G115 -- current time
	msg = append(append(msg, iv...), ct...)
	mac := hmac.New(sha256.New, raw[:16])
	mac.Write(msg)
	return []byte(base64.URLEncoding.EncodeToString(mac.Sum(msg)))
}

type githubLab struct {
	RuntimeDir string `json:"runtime_dir"`
	CAFile     string `json:"ca_file"`
	Services   map[string]struct {
		BaseURL string `json:"base_url"`
		Client  struct {
			ID         string `json:"id"`
			SecretFile string `json:"secret_file"`
		} `json:"client"`
	} `json:"services"`
}

// labAccounts adapts the migrated account store to github.Accounts.
type labAccounts struct{ s *accounts.Service }

func (a labAccounts) AccountTx(ctx context.Context, tx *store.Tx, id int64) (github.Account, error) {
	acc, err := a.s.GetTx(ctx, tx, id)
	return github.Account{ID: acc.ID, Username: acc.Username, Locked: acc.IsLocked, Generation: acc.AuthGeneration, Managed: string(acc.Managed)}, err
}
func (a labAccounts) ProvisionTx(ctx context.Context, tx *store.Tx, name, manager string) (int64, error) {
	return a.s.ProvisionTx(ctx, tx, name, manager)
}
func (a labAccounts) ReleaseTx(ctx context.Context, tx *store.Tx, id int64, hash string) error {
	return a.s.ReleaseTx(ctx, tx, id, hash)
}

type labSignIn struct{ signed []int64 }

func (l *labSignIn) SignInExternal(w http.ResponseWriter, _ *http.Request, in auth.ExternalSignIn) error {
	l.signed = append(l.signed, in.UserID)
	w.WriteHeader(http.StatusFound)
	return nil
}

func (*labSignIn) RenewAfter(http.ResponseWriter, *http.Request, principal.Reason, func(context.Context, *store.Tx) error) error {
	return fault.New(fault.Internal, "")
}

// E04 and E06 functionally: the golden data set with the lab stub's
// client secret encrypted as Python stores it and the stub's user ids on
// both GitHub identities migrates, and a sign-in at the stub reaches the
// same accounts through the migrated configuration, unchanged.
func TestLabGitHubSignInAfterMigration(t *testing.T) {
	path := os.Getenv("WEBSSH_LAB_JSON")
	if path == "" {
		path = filepath.Join("..", "..", "..", "tests", "lab", "runtime", "lab.json")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("lab not available (set WEBSSH_LAB_JSON): %v", err)
	}
	var lab githubLab
	if err := json.Unmarshal(data, &lab); err != nil {
		t.Fatal(err)
	}
	stub := lab.Services["github-stub"]
	secretRaw, err := os.ReadFile(filepath.Join(lab.RuntimeDir, stub.Client.SecretFile))
	if err != nil {
		t.Fatal(err)
	}
	secret, _, _ := strings.Cut(string(secretRaw), "\n")
	pem, err := os.ReadFile(filepath.Join(lab.RuntimeDir, lab.CAFile))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem)
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}

	dir := copyGolden(t)
	key := golden.manifest.SecretKey.Value
	execLegacySQL(t, dir,
		`UPDATE github_identities SET github_user_id = '1001' WHERE github_user_id = '90000002'`,
		`UPDATE github_identities SET github_user_id = '1003' WHERE github_user_id = '90000001'`)
	execSQLArgs(t, filepath.Join(dir, "app.db"), `UPDATE github_auth_configuration SET enabled = 1, allowed_orgs_json = '[]', client_id = ?, encrypted_client_secret = ?`,
		stub.Client.ID, fernetPurposeEncrypt(t, githubPurpose, key, []byte(strings.TrimRight(secret, "\r"))))
	m := migrateM1(t, dir, key, M1{})

	signIn := &labSignIn{}
	svc := &github.Service{DB: m.db, Ring: m.ring, Accounts: labAccounts{&accounts.Service{DB: m.db}}, SignIn: signIn,
		Client:  github.Client{WebURL: stub.BaseURL, APIURL: stub.BaseURL, HTTP: hc},
		Binding: func(*http.Request) string { return "lab-binding" }}
	mux := http.NewServeMux()
	svc.Register(mux)
	for _, c := range []struct{ login, user string }{{"octo-alice", "github_linked"}, {"octo-carol", "octo_golden"}} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest("GET", "/auth/github/login", nil))
		if rec.Code != http.StatusFound {
			t.Fatalf("login: %d %s", rec.Code, rec.Body)
		}
		noFollow := *hc
		noFollow.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		resp, err := noFollow.Get(rec.Header().Get("Location") + "&login=" + url.QueryEscape(c.login))
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		loc, err := url.Parse(resp.Header.Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		rec = httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest("GET", "/auth/github/callback?"+loc.RawQuery, nil))
		want := goldenUserByName(t, c.user).ID
		if rec.Code != http.StatusFound || signIn.signed[len(signIn.signed)-1] != want {
			t.Fatalf("%s: %d %s, signed %v, want %d", c.login, rec.Code, rec.Body, signIn.signed, want)
		}
	}
}

func execSQLArgs(t *testing.T, path, query string, args ...any) {
	t.Helper()
	db, err := driver.Open("file:" + filepath.ToSlash(path))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.ExecContext(t.Context(), query, args...); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
}
