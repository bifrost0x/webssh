package vault

import (
	"bytes"
	"context"
	"encoding/json/jsontext"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/principal/principaltest"
	"github.com/bifrost0x/webssh/internal/store"
)

func TestImportLegacyVault(t *testing.T) {
	t.Parallel()
	o := readCredentialOracle(t)
	for _, v := range o.Vaults {
		t.Run("v"+string(rune('0'+v.Version)), func(t *testing.T) {
			t.Parallel()
			r := newCredRig(t)
			p := principaltest.User(o.User)
			r.stores.set(o.User, o.records())
			if err := r.db.Write(t.Context(), func(tx *store.Tx) error {
				return ImportLegacyVaultTx(t.Context(), tx, o.User, []byte(v.Document), v.Version)
			}); err != nil {
				t.Fatal(err)
			}
			if !r.state(t, p).LegacyVault {
				t.Fatal("the legacy vault is not offered")
			}
			if _, err := r.doGrant(t, p, MethodImport, "", map[string]any{"passphrase": "a wrong but long passphrase"}, "issue"); codeOf(err) != fault.VaultUnlockFailed {
				t.Fatalf("wrong passphrase: %v", err)
			}
			if n := len(r.state(t, p).Credentials); n != 0 {
				t.Fatalf("a failed import created %d passwords", n)
			}
			if _, err := r.do(t, p, MethodImport, "", map[string]any{"passphrase": o.Passphrase}); err != nil {
				t.Fatal(err)
			}
			st := r.state(t, p)
			if len(st.Credentials) != len(v.Records) || st.LegacyVault {
				t.Fatalf("after import: %d passwords, offered %v", len(st.Credentials), st.LegacyVault)
			}
			for _, c := range st.Credentials {
				if c.Username != "" {
					t.Errorf("imported username %q", c.Username)
				}
			}
			if s, _ := st.profile("p1"); s != "ready" {
				t.Errorf("p1 after import: %s", s)
			}
			secret, err := r.svc.Password(t.Context(), o.User, "p1", ResourcesFromRecords(o.records())[0].Target)
			if err != nil || string(secret) != v.Records["p1"].Password {
				t.Errorf("imported password of p1: %v", err)
			}
			if _, err := r.do(t, p, MethodImport, "", map[string]any{"passphrase": o.Passphrase}); err != nil {
				t.Fatal(err)
			}
			if n := len(r.state(t, p).Credentials); n != len(v.Records) {
				t.Errorf("a second import of the same document created passwords (%d)", n)
			}
		})
	}
}

func TestImportLegacyVaultFailures(t *testing.T) {
	t.Parallel()
	r := newCredRig(t)
	p := principaltest.User(7)
	if _, err := r.doGrant(t, p, MethodImport, "", map[string]any{"passphrase": "long enough passphrase"}, "issue"); codeOf(err) != fault.VaultMissing {
		t.Errorf("no vault: %v", err)
	}
	o := readCredentialOracle(t)
	if err := r.db.Write(t.Context(), func(tx *store.Tx) error {
		return ImportLegacyVaultTx(t.Context(), tx, 7, []byte(o.Vaults[1].Document), 2)
	}); err != nil {
		t.Fatal(err)
	}
	for pass, code := range map[any]fault.Code{"short": fault.InvalidPassphrase, 5: fault.InvalidRequest, strings.Repeat("x", 1025): fault.InvalidRequest} {
		if _, err := r.do(t, p, MethodImport, "", map[string]any{"passphrase": pass}); codeOf(err) != code {
			t.Errorf("passphrase %v: %v, want %s", pass, err, code)
		}
	}
	for _, doc := range []string{`{}`, `{"version":3,"kdf":"scrypt-131072-8-1","salt":"","nonce":"","ciphertext":""}`,
		`{"version":2,"kdf":"scrypt-131072-8-1","salt":"AA==","nonce":"AA==","ciphertext":"AA=="}`, `not json`} {
		if _, err := parseLegacyVault([]byte(doc)); codeOf(err) != fault.VaultUnreadable {
			t.Errorf("%s: %v", doc, err)
		}
	}
}

// TestSecretsNeverLogged runs every route with a password and a failing
// store and checks the log and the answers for the plaintext.
func TestSecretsNeverLogged(t *testing.T) {
	t.Parallel()
	const secret = "s3cr3t-never-logged-Ω"
	r := newCredRig(t)
	var logs bytes.Buffer
	h := &CredentialsHTTP{Service: r.svc, HTTPS: func(*http.Request) bool { return true },
		Index: func(*http.Request) string { return "/" }, Logger: slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))}
	mux := http.NewServeMux()
	h.Register(mux)
	p := principaltest.User(1)
	r.stores.set(1, Records{Profiles: []jsontext.Value{profileJSON("p1", "a.example")}, SMB: true})
	send := func(method, path, body string, grant string) (int, string) {
		req := httptest.NewRequest(method, path, strings.NewReader(body)).WithContext(principal.With(context.Background(), p))
		req.Header.Set(StepUpHeader, grant)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}
	prepare := func(mutation string) string {
		_, out := send("POST", "/api/credentials/intents", `{"operation":"native","mutation":`+mutation+`}`, "")
		i := strings.Index(out, `"intent":"`)
		if i < 0 {
			t.Fatalf("intent: %s", out)
		}
		return out[i+10 : i+10+43]
	}
	tok := prepare(`{"method":"create","name":"n","password":"` + secret + `"}`)
	code, out := send("POST", "/api/credentials", `{"intent":"`+tok+`","name":"n","password":"`+secret+`"}`, "")
	if code != 200 {
		t.Fatalf("create: %d %s", code, out)
	}
	r.stores.fail = errStoreDown
	tok = prepare(`{"method":"create","name":"m","password":"` + secret + `"}`)
	code, out2 := send("POST", "/api/credentials", `{"intent":"`+tok+`","name":"m","password":"`+secret+`"}`, "")
	if code != 500 {
		t.Errorf("failing store: %d %s", code, out2)
	}
	for _, text := range []string{logs.String(), out, out2} {
		if strings.Contains(text, secret) || strings.Contains(text, "s3cr3t") {
			t.Fatalf("the plaintext leaked: %s", text)
		}
	}
	if !strings.Contains(logs.String(), "credential request failed") {
		t.Error("the storage failure was not logged")
	}
}

func TestHTTPNeedsHTTPS(t *testing.T) {
	t.Parallel()
	r := newCredRig(t)
	h := &CredentialsHTTP{Service: r.svc, HTTPS: func(*http.Request) bool { return false }, Index: func(*http.Request) string { return "/root/" }}
	mux := http.NewServeMux()
	h.Register(mux)
	ctx := principal.With(context.Background(), principaltest.User(1))
	for _, c := range []struct{ method, path string }{{"GET", "/api/credentials/state"}, {"POST", "/api/credentials/intents"}, {"POST", "/api/credentials"}} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(c.method, c.path, strings.NewReader("{}")).WithContext(ctx))
		if rec.Code != 403 || !strings.Contains(rec.Body.String(), `"code":"https_required"`) {
			t.Errorf("%s %s: %d %s", c.method, c.path, rec.Code, rec.Body)
		}
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("GET", "/credentials", nil).WithContext(ctx))
	if rec.Code != 302 || rec.Header().Get("Location") != "/root/#passwords" {
		t.Errorf("page: %d %s", rec.Code, rec.Header().Get("Location"))
	}
}

var errStoreDown = errors.New("store down")
